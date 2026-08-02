package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/josh/mw2-rpcs3/internal/auth"
	"github.com/josh/mw2-rpcs3/internal/capture"
	"github.com/josh/mw2-rpcs3/internal/protocol"
)

func main() {
	max := flag.Uint("max-frame", 1<<20, "maximum payload bytes")
	jsonl := flag.Bool("jsonl", false, "read capture JSONL instead of raw frames")
	qos := flag.Bool("qos", false, "read fixed-size QoS telemetry records")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mw2-inspect [-jsonl|-qos] FILE")
		os.Exit(2)
	}
	file, err := os.Open(flag.Arg(0))
	if err != nil {
		fatal(err)
	}
	defer file.Close()
	if *qos {
		inspectQoS(file)
		return
	}
	if *jsonl {
		inspectJSONL(file, uint32(*max))
		return
	}
	inspectFrames(file, uint32(*max))
}

func inspectQoS(r io.Reader) {
	const recordSize = 96
	record := make([]byte, recordSize)
	for index := 0; ; index++ {
		_, err := io.ReadFull(r, record)
		if err == io.EOF {
			return
		}
		if err != nil {
			fatal(err)
		}
		if string(record[:4]) != "QOS1" {
			fatal(fmt.Errorf("record %d has invalid magic %x", index, record[:4]))
		}
		version := binary.BigEndian.Uint16(record[4:6])
		tag := binary.BigEndian.Uint16(record[6:8])
		if version != 3 || tag != 3 {
			fmt.Printf("record=%d version=%d tag=%d raw=%s\n", index, version, tag, hex.EncodeToString(record))
			continue
		}
		fmt.Printf("record=%d version=%d tag=%d stage=%d call_r3=%016x call_r4=%016x sockaddr_len=%d sockaddr_family=%d remote=%d.%d.%d.%d:%d global_port=%d ready=%d controller_state=%d join_state=%d lobby_r28=%016x lobby_r27=%016x lobby_r30=%016x r31_id=%08x r27_id=%08x r30_id=%08x lobby_r31=%016x\n",
			index,
			version,
			tag,
			binary.BigEndian.Uint16(record[8:10]),
			binary.BigEndian.Uint64(record[16:24]),
			binary.BigEndian.Uint64(record[24:32]),
			record[32], record[33],
			record[36], record[37], record[38], record[39],
			binary.BigEndian.Uint16(record[34:36]),
			binary.BigEndian.Uint16(record[40:42]),
			record[42],
			record[43],
			binary.BigEndian.Uint32(record[44:48]),
			binary.BigEndian.Uint64(record[48:56]),
			binary.BigEndian.Uint64(record[56:64]),
			binary.BigEndian.Uint64(record[64:72]),
			binary.BigEndian.Uint32(record[72:76]),
			binary.BigEndian.Uint32(record[76:80]),
			binary.BigEndian.Uint32(record[80:84]),
			binary.BigEndian.Uint64(record[88:96]),
		)
	}
}

func inspectFrames(r io.Reader, max uint32) {
	for index := 0; ; index++ {
		frame, err := protocol.ReadFrame(r, max)
		if err == io.EOF {
			return
		}
		if err != nil {
			fatal(err)
		}
		fmt.Printf("frame=%d kind=%d service=%d task=%d tx=%d flags=%d payload=%d hex=%s\n", index, frame.Kind, frame.Service, frame.Task, frame.Transaction, frame.Flags, len(frame.Payload), hex.EncodeToString(frame.Payload))
	}
}

func inspectJSONL(r io.Reader, max uint32) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16<<20)
	sessions := make(map[string]*inspectionSession)
	for scanner.Scan() {
		var record capture.Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			fatal(err)
		}
		payload, err := hex.DecodeString(record.Payload)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%s %s %s %s bytes=%d sha256=%s\n", record.Timestamp.Format("2006-01-02T15:04:05Z"), record.Listener, record.Direction, record.Remote, record.Length, record.SHA256)
		if inspectDemonwareRecord(record, payload, sessions) {
			continue
		}
		inspectFrames(bytes.NewReader(payload), max)
	}
	if err := scanner.Err(); err != nil {
		fatal(err)
	}
}

type inspectionSession struct {
	authResponse auth.ParsedLegacySuccessResponse
	platformKey  [24]byte
	hasAuth      bool
	hasKey       bool
}

func inspectDemonwareRecord(record capture.Record, payload []byte, sessions map[string]*inspectionSession) bool {
	session := sessions[remoteHost(record.Remote)]
	if session == nil {
		session = &inspectionSession{}
		sessions[remoteHost(record.Remote)] = session
	}

	switch record.Listener {
	case "auth":
		if record.Direction == "out" {
			parsed, err := auth.ParseLegacySuccessResponse(payload)
			if err != nil {
				fmt.Printf("  auth_response parse_error=%q\n", err)
				return true
			}
			session.authResponse = parsed
			session.hasAuth = true
			fmt.Printf("  auth_response status=%d iv_seed=%08x client_session_key=%s", parsed.Status, parsed.IVSeed, hex.EncodeToString(parsed.SessionKey[:]))
			if session.hasKey {
				key, keyErr := parsed.LSGSessionKey(session.platformKey[:])
				if keyErr != nil {
					fmt.Printf(" lsg_key_error=%q\n", keyErr)
					return true
				}
				fmt.Printf(" lsg_session_key=%s source=decrypted_game_ticket\n", hex.EncodeToString(key[:]))
				return true
			}
			fmt.Println(" lsg_session_key=unavailable")
			return true
		}
		request, err := auth.ParseRetailAuthRequest(payload)
		if err != nil {
			fmt.Printf("  auth_request parse_error=%q\n", err)
			return true
		}
		if len(request.Ticket) >= 56 {
			copy(session.platformKey[:], request.Ticket[32:56])
			session.hasKey = true
		}
		fmt.Printf("  auth_request game_id=%08x ticket_bytes=%d platform_key_available=%t\n", request.GameID, len(request.Ticket), session.hasKey)
		return true
	case "lsg":
		recordData, err := auth.ParseLSGRecord(payload)
		if err != nil {
			fmt.Printf("  lsg_record parse_error=%q\n", err)
			return true
		}
		if !recordData.Encrypted {
			messageType := byte(0)
			if len(recordData.Payload) > 0 {
				messageType = recordData.Payload[0]
			}
			fmt.Printf("  lsg_record encrypted=false message_type=%02x payload_bytes=%d\n", messageType, len(recordData.Payload))
			return true
		}
		if !session.hasAuth || !session.hasKey {
			fmt.Printf("  lsg_record encrypted=true iv_seed=%08x payload_bytes=%d session_key=unavailable\n", recordData.IVSeed, len(recordData.Payload))
			return true
		}
		key, keyErr := session.authResponse.LSGSessionKey(session.platformKey[:])
		if keyErr != nil {
			fmt.Printf("  lsg_record encrypted=true iv_seed=%08x key_error=%q key_source=decrypted_game_ticket\n", recordData.IVSeed, keyErr)
			return true
		}
		decrypted, err := auth.DecryptLSGRecord(payload, key[:])
		if err != nil {
			fmt.Printf("  lsg_record encrypted=true iv_seed=%08x decrypt_error=%q key_source=decrypted_game_ticket\n", recordData.IVSeed, err)
			return true
		}
		fmt.Printf("  lsg_record encrypted=true iv_seed=%08x message_type=%02x hmac_valid=%t key_source=decrypted_game_ticket message_hex=%s\n", decrypted.IVSeed, decrypted.MessageType, decrypted.HMACValid, hex.EncodeToString(decrypted.Message))
		return true
	default:
		return false
	}
}

func remoteHost(remote string) string {
	host, _, err := net.SplitHostPort(remote)
	if err == nil {
		return host
	}
	return strings.Trim(remote, "[]")
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
