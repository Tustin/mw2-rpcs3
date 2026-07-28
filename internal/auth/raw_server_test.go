package auth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

func TestReadRetailRequest(t *testing.T) {
	for _, bodySize := range []int{minRetailRequestBodySize, LegacyRetailRequestSize - 4, maxRetailRequestBodySize} {
		want := makeRetailRequest(0x14a0, candidateSessionKey)[:4+bodySize]
		binary.LittleEndian.PutUint32(want[:4], uint32(bodySize))
		got, err := ReadRetailRequest(bytes.NewReader(want))
		if err != nil {
			t.Fatalf("body size %d: %v", bodySize, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("body size %d: request mismatch", bodySize)
		}
	}
}

func TestReadRetailRequestRejectsTruncatedInput(t *testing.T) {
	request := makeRetailRequest(0x14a0, candidateSessionKey)
	_, err := ReadRetailRequest(bytes.NewReader(request[:len(request)-1]))
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected unexpected EOF, got %v", err)
	}
}

func TestValidateRetailRequest(t *testing.T) {
	minSize := 4 + minRetailRequestBodySize
	for _, size := range []int{minSize, LegacyRetailRequestSize, RetailRequestSize} {
		if err := ValidateRetailRequest(make([]byte, size)); err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
	}
	for _, size := range []int{minSize - 1, RetailRequestSize + 1} {
		if err := ValidateRetailRequest(make([]byte, size)); err == nil {
			t.Fatalf("size %d: expected size error", size)
		}
	}
}

func TestParseRetailAuthRequest(t *testing.T) {
	request := makeRetailRequest(0x14a0, candidateSessionKey)
	parsed, err := ParseRetailAuthRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.GameID != 0x14a0 {
		t.Fatalf("game ID=%08x", parsed.GameID)
	}
	if len(parsed.Ticket) != 284 {
		t.Fatalf("ticket length=%d", len(parsed.Ticket))
	}
	if !bytes.Equal(parsed.Ticket[32:56], candidateSessionKey[:]) {
		t.Fatalf("ticket bytes=%x", parsed.Ticket[32:56])
	}
}

func TestSummarizeRequest(t *testing.T) {
	request := make([]byte, RetailRequestSize)
	copy(request[20:], []byte("UP0002-BLUS30377_00"))
	summary := SummarizeRequest(request)
	if len(summary.SHA256) != 64 {
		t.Fatalf("unexpected digest %q", summary.SHA256)
	}
	if len(summary.Strings) != 1 || summary.Strings[0] != "UP0002-BLUS30377_00" {
		t.Fatalf("unexpected strings %#v", summary.Strings)
	}
}

func TestBuildLegacySuccessResponse(t *testing.T) {
	const ivSeed = 0x13371337
	response, details, err := buildLegacySuccessResponse(candidateSessionKey[:], 0x14a0, candidateSessionKey, ivSeed)
	if err != nil {
		t.Fatal(err)
	}
	if len(response) != 295 {
		t.Fatalf("response length=%d", len(response))
	}
	wantPrefix := []byte{0x23, 0x01, 0x00, 0x00, 0x00, 0x13, 0x78, 0x05, 0x00, 0x00, 0x6e, 0x26, 0x6e, 0x26}
	if !bytes.Equal(response[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("unexpected response prefix %x", response[:len(wantPrefix)])
	}
	if details.IVSeed != ivSeed {
		t.Fatalf("iv seed=%08x", details.IVSeed)
	}
	if details.SessionKey != candidateSessionKey {
		t.Fatalf("session key=%x", details.SessionKey)
	}
	reader := newLSBBitReader(response[6:])
	if errorFlag, err := reader.readBits(1); err != nil || errorFlag != 0 {
		t.Fatalf("error flag=%d err=%v", errorFlag, err)
	}
	for _, field := range []struct {
		name string
		want uint32
	}{
		{name: "status", want: bdAuthNoError},
		{name: "iv seed", want: ivSeed},
	} {
		got, err := reader.readBits(32)
		if err != nil || uint32(got) != field.want {
			t.Fatalf("%s=%08x err=%v", field.name, got, err)
		}
	}
	gotEncryptedTicket, err := reader.readBytes(legacyTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotEncryptedTicket, details.EncryptedGameTicket[:]) {
		t.Fatalf("wire encrypted ticket=%x", gotEncryptedTicket)
	}
	gotSessionKey, err := reader.readBytes(len(candidateSessionKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSessionKey, candidateSessionKey[:]) {
		t.Fatalf("wire session key=%x", gotSessionKey)
	}
	gotLSGTicket, err := reader.readBytes(legacyTicketLen)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotLSGTicket, details.LSGTicket[:]) {
		t.Fatalf("wire LSG ticket=%x", gotLSGTicket)
	}
	if reader.remainingBits() != 7 {
		t.Fatalf("remaining padding bits=%d", reader.remainingBits())
	}

	ticket := details.GameTicket[:]
	if got := binary.LittleEndian.Uint32(ticket[0x00:0x04]); got != legacyTicketMagic {
		t.Fatalf("ticket magic=%08x", got)
	}
	if ticket[0x04] != legacyTicketType {
		t.Fatalf("ticket type=%02x", ticket[0x04])
	}
	if got := binary.LittleEndian.Uint32(ticket[0x05:0x09]); got != 0x14a0 {
		t.Fatalf("ticket game ID=%08x", got)
	}
	if !bytes.Equal(ticket[0x09:0x19], bytes.Repeat([]byte{0x0a}, 16)) {
		t.Fatalf("ticket reserved bytes=%x", ticket[0x09:0x19])
	}
	if got := binary.LittleEndian.Uint64(ticket[0x19:0x21]); got != legacyUserID {
		t.Fatalf("user ID=%016x", got)
	}
	if got := string(bytes.TrimRight(ticket[0x21:0x61], "\x00")); got != legacyUsername {
		t.Fatalf("username=%q", got)
	}
	if !bytes.Equal(ticket[0x61:0x79], candidateSessionKey[:]) {
		t.Fatalf("game ticket session key mismatch: %x", ticket[0x61:0x79])
	}
	if !bytes.Equal(ticket[0x79:0x80], bytes.Repeat([]byte{0x0a}, 7)) {
		t.Fatalf("game ticket padding=%x", ticket[0x79:0x80])
	}
	if !bytes.Equal(details.LSGTicket[:24], candidateSessionKey[:]) {
		t.Fatalf("LSG session key mismatch: %x", details.LSGTicket[:24])
	}
}

func makeRetailRequest(gameID uint32, platformKey [24]byte) []byte {
	ticket := make([]byte, 284)
	copy(ticket[32:56], platformKey[:])
	payload := newLSBBitWriter(1 + 3*(5+32) + len(ticket)*8)
	payload.writeBit(true)
	for _, value := range []uint32{0x20254e8d, gameID, uint32(len(ticket))} {
		for bit := 0; bit < 5; bit++ {
			payload.writeBit(8&(1<<bit) != 0)
		}
		payload.writeBytes(littleEndianUint32(value))
	}
	payload.writeBytes(ticket)
	request := make([]byte, RetailRequestSize)
	binary.LittleEndian.PutUint32(request[:4], maxRetailRequestBodySize)
	request[4] = 0
	request[5] = 0x12
	copy(request[6:], payload.bytes())
	return request
}

func TestCapturedMW2SuccessResponse(t *testing.T) {
	if len(capturedMW2SuccessResponse) != 295 {
		t.Fatalf("response length=%d", len(capturedMW2SuccessResponse))
	}
	parsed, err := ParseLegacySuccessResponse(capturedMW2SuccessResponse)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Status != bdAuthNoError {
		t.Fatalf("status=%d", parsed.Status)
	}
	wantKey := []byte{0x3b, 0xb4, 0x3f, 0x03, 0xb3, 0x69, 0x6f, 0xb6, 0xf2, 0xb3, 0xfa, 0x1d, 0x21, 0xba, 0xd2, 0xb8, 0xac, 0xcd, 0x98, 0x7c, 0x94, 0x75, 0x9f, 0x27}
	if !bytes.Equal(parsed.SessionKey[:], wantKey) {
		t.Fatalf("session key=%x", parsed.SessionKey)
	}
	wantProofSuffix := []byte{0x7b, 0xf4, 0x7a, 0x9a, 0x67, 0x6f, 0x6c, 0xfb, 0x14, 0x57, 0x74, 0xc1, 0x2e, 0x5d, 0x31, 0x9c, 0xcf, 0x15, 0x36, 0x3f, 0x44, 0x00, 0xea, 0xcd}
	if !bytes.Equal(parsed.PlatformProof[len(parsed.PlatformProof)-len(wantProofSuffix):], wantProofSuffix) {
		t.Fatalf("platform proof suffix=%x", parsed.PlatformProof[len(parsed.PlatformProof)-len(wantProofSuffix):])
	}
}

func TestRawServerHandlesServiceTaskAfterHello(t *testing.T) {
	client, server := net.Pipe()
	service := NewRawServer("", slog.New(slog.NewTextHandler(io.Discard, nil)), capture.New(false, "", RetailRequestSize), time.Second, time.Second)
	var ticket [legacyTicketLen]byte
	copy(ticket[:24], candidateSessionKey[:])
	service.sessionStore().putWithPendingKey(ticket, [24]byte{}, candidateSessionKey)
	done := make(chan struct{})
	go func() {
		service.handle(server)
		close(done)
	}()

	if _, err := client.Write(buildLSGInitialRecord(mw2GameID, 0x9f08a100, ticket)); err != nil {
		t.Fatal(err)
	}
	if _, err := readLSGFrame(client, RetailRequestSize); err != nil {
		t.Fatal(err)
	}

	taskFrame, err := EncryptLSGRecord(bdServiceTitleUtilities, []byte{bdTypeU8, 6}, 0x312d52ee, candidateSessionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(taskFrame); err != nil {
		t.Fatal(err)
	}
	response, err := readLSGFrame(client, RetailRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	session := &lsgConnection{key: candidateSessionKey}
	messageType, payload, err := session.decryptResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != lsgTaskReplyType || payload[14] != bdTypeU8 || payload[15] != 6 {
		t.Fatalf("unexpected task response type=%d payload=%x", messageType, payload)
	}

	_ = client.Close()
	<-done
}

func TestRawServerSendsDynamicLSGHello(t *testing.T) {
	for _, gameID := range []uint32{mw2GameID, 0} {
		t.Run(fmt.Sprintf("game_%08x", gameID), func(t *testing.T) {
			client, server := net.Pipe()
			service := NewRawServer("", slog.New(slog.NewTextHandler(io.Discard, nil)), capture.New(false, "", RetailRequestSize), time.Second, time.Second)
			var ticket [legacyTicketLen]byte
			copy(ticket[:24], candidateSessionKey[:])
			service.sessionStore().put(ticket, candidateSessionKey)
			done := make(chan struct{})
			go func() {
				service.handle(server)
				close(done)
			}()

			initial := buildLSGInitialRecord(gameID, 0x9f08a100, ticket)
			if len(initial) != 152 || binary.LittleEndian.Uint32(initial[:4]) != 0xb4 {
				t.Fatalf("unexpected initial LSG record length: %d", len(initial))
			}
			if _, err := client.Write(initial); err != nil {
				t.Fatal(err)
			}
			response, err := readLSGFrame(client, RetailRequestSize)
			if err != nil {
				t.Fatal(err)
			}
			if len(response) != 14 || response[4] != 0 {
				t.Fatalf("unexpected LSG hello response: %x", response)
			}
			reader := newLSBBitReader(response[5:])
			if dataType, err := reader.readBits(5); err != nil || dataType != 4 {
				t.Fatalf("unexpected LSG connection-ID type: %d, %v", dataType, err)
			}
			if _, err := reader.readBytes(8); err != nil {
				t.Fatal(err)
			}
			_ = client.Close()
			<-done
			if service.LSGConnections() != 1 || service.LSGFrames() != 1 {
				t.Fatalf("lsg connections=%d frames=%d", service.LSGConnections(), service.LSGFrames())
			}
		})
	}
}

func TestRawServerInjectsSharedMatchmakingStore(t *testing.T) {
	service := NewRawServer(
		"",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		capture.New(false, "", RetailRequestSize),
		time.Second,
		time.Second,
	)
	first, err := service.newLSGConnection(candidateSessionKey, candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.newLSGConnection(candidateSessionKey, candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if first.matchmakingSessions == nil ||
		first.matchmakingSessions != second.matchmakingSessions ||
		first.matchmakingSessions != service.matchmakingSessions {
		t.Fatal("LSG connections do not share the RawServer matchmaking directory")
	}
}

func buildLSGInitialRecord(gameID, randomNumber uint32, ticket [legacyTicketLen]byte) []byte {
	payload := newLSBBitWriter(1 + 5 + 32 + 5 + 32 + legacyTicketLen*8)
	payload.writeBit(true)
	writeTypedUint32(payload, gameID)
	writeTypedUint32(payload, randomNumber)
	payload.writeBytes(ticket[:])
	inner := make([]byte, 2+len(payload.bytes()))
	inner[1] = lsgInitialServiceType
	copy(inner[2:], payload.bytes())
	record := make([]byte, 12+len(inner))
	binary.LittleEndian.PutUint32(record[:4], uint32(len(record)+28))
	record[4] = 0xff
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(inner)))
	copy(record[12:], inner)
	return record
}

func writeTypedUint32(writer *lsbBitWriter, value uint32) {
	for bit := 0; bit < 5; bit++ {
		writer.writeBit(8&(1<<bit) != 0)
	}
	writer.writeBytes(littleEndianUint32(value))
}

func TestRetailAuthRequestLSGSessionKey(t *testing.T) {
	request := mustDecodeHex("2c010000001291d8302d1502a50000401c0100002101000000000114300000c0000800143137373235300000000000000000000000000000000001000400000100000700080000019fa494d1a0000700080000019fa4a28d400002000800000000000189a60004002054757374696e000000000000000000000000000000000000000000000000000800046272000000040004756e0000000800185550303030322d424c555333303337375f30300000000000000100040000000000080018636f3853766d5371467769354c6d7349525257746f6c794c00000000000000003002004c000800045250434e00080040303e021d00968b2fdb243bfd06cfd335c8090224f4ecdfed9c62db39cbef0df8ac021d00d0dbeaa6098e6bb1e8ded33c1636ee91220860707ef65b8b2b8d0c18")
	request = append(request, 0)
	parsed, err := ParseRetailAuthRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsePS3LSGSessionKey(parsed.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	marker := bytes.Index(parsed.Ticket, []byte(ps3RPCNPlatformTicketMarker))
	if marker < 0 {
		t.Fatalf("RPCN marker not found in ticket")
	}
	var want [24]byte
	copy(want[:], parsed.Ticket[marker-ps3RPCNKeyMarkerDelta:])
	if !bytes.Equal(got[:], want[:]) {
		t.Fatalf("RPCN LSG session key=%x want=%x", got, want)
	}
	if bytes.Equal(got[:], make([]byte, 24)) {
		t.Fatalf("RPCN LSG session key must not be all zero")
	}
}

func TestRetailAuthRequestLegacyLSGSessionKey(t *testing.T) {
	ticket := make([]byte, ps3LSGSessionKeyOffset+24)
	want := mustDecodeHex("4d57322d52504353332d53455353494f4e2d4b45592d3031")
	copy(ticket[ps3LSGSessionKeyOffset:], want)
	got, err := parsePS3LSGSessionKey(ticket)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want) {
		t.Fatalf("legacy LSG session key=%x", got)
	}
}

func TestRawServerSendsDynamicSuccess(t *testing.T) {
	client, server := net.Pipe()
	service := &RawServer{log: slog.New(slog.NewTextHandler(io.Discard, nil)), readTimeout: time.Second, writeTimeout: time.Second, recorder: capture.New(false, "", RetailRequestSize)}
	done := make(chan struct{})
	go func() {
		service.handle(server)
		close(done)
	}()

	request := makeRetailRequest(0x14a0, candidateSessionKey)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, 295)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseLegacySuccessResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Status != bdAuthNoError || parsed.SessionKey == ([24]byte{}) {
		t.Fatalf("unexpected dynamic response status=%d key=%x", parsed.Status, parsed.SessionKey)
	}
	var ticketID [24]byte
	copy(ticketID[:], parsed.PlatformProof[:len(ticketID)])
	stored, ok := service.sessionStore().sessions[ticketID]
	if !ok {
		t.Fatal("dynamic LSG ticket was not retained")
	}
	if stored.key != ([24]byte{}) {
		t.Fatalf("unexpected synthetic request LSG key=%x", stored.key)
	}
	_ = client.Close()
	<-done
	if service.Requests() != 1 {
		t.Fatalf("requests=%d", service.Requests())
	}
}

func TestRetailDiagnosticLogsDoNotExposeRawSecrets(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewTextHandler(&output, nil))
	secret := []byte("TOP-SECRET-RPCN-MARKER")
	ticket := make([]byte, 96)
	copy(ticket[16:], secret)
	var key [24]byte
	copy(key[:], secret)

	logTicketKeyDiagnostic(log, ticket, key)
	logLSGRequest(log, 2, 0xfe, secret)
	logLSGResponsePayload(log, 2, 1, secret, &lsgConnection{})
	logLSGEncryptedResponse(log, 2, 1, secret)
	frame, err := EncryptLSGRecord(0xfe, secret, 7, key[:])
	if err != nil {
		t.Fatalf("encrypt diagnostic frame: %v", err)
	}
	(&lsgConnection{key: key}).diagnoseRequest(log, 3, frame)

	text := output.String()
	for _, forbidden := range []string{
		string(secret),
		fmt.Sprintf("%x", secret),
		"ticket_hex",
		"extracted_key_hex",
		"payload_hex",
		"frame_hex",
		"plaintext_hex",
		"visible_strings",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("diagnostic log contains forbidden value %q: %s", forbidden, text)
		}
	}
}

func TestSensitiveLoggingIsExplicitAndIncludesRawEvidence(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewTextHandler(&output, nil))
	service := &RawServer{logSensitive: true}
	secret := []byte("credential-bearing-test-data")

	service.logSensitiveEvent(log, "sensitive test event",
		"payload_hex", hex.EncodeToString(secret),
	)

	text := output.String()
	if !strings.Contains(text, "sensitive=true") ||
		!strings.Contains(text, hex.EncodeToString(secret)) {
		t.Fatalf("sensitive evidence missing from explicit diagnostic log: %s", text)
	}
}

func TestStorageResponseLogReportsTypeCheckingMarker(t *testing.T) {
	var output bytes.Buffer
	log := slog.New(slog.NewTextHandler(&output, nil))
	connection := &lsgConnection{
		lastServiceID: bdServiceStorage,
		playlistBytes: 3,
	}

	logLSGResponsePayload(log, 4, lsgTaskReplyType, connection.storageListReply([]byte("ABC")), connection)

	text := output.String()
	for _, expected := range []string{
		"type_checked=true",
		"operation_id=8",
		"result_count=1",
		"file_size=3",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("response log is missing %q: %s", expected, text)
		}
	}
}
