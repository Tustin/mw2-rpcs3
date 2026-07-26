package auth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

const (
	LegacyRetailRequestSize  = 304
	RetailRequestSize        = 320
	minRetailRequestBodySize = 298
	maxRetailRequestBodySize = RetailRequestSize - 4
)

var ObservedRejection = []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x13, 0xc4, 0x05, 0x00, 0x00, 0x00}

type RequestSummary struct {
	SHA256  string
	Strings []string
}

type RawServer struct {
	addr         string
	log          *slog.Logger
	recorder     *capture.Recorder
	readTimeout  time.Duration
	writeTimeout time.Duration
	connections  atomic.Uint64
	requests     atomic.Uint64
}

func NewRawServer(addr string, log *slog.Logger, recorder *capture.Recorder, readTimeout, writeTimeout time.Duration) *RawServer {
	return &RawServer{addr: addr, log: log, recorder: recorder, readTimeout: readTimeout, writeTimeout: writeTimeout}
}

func (s *RawServer) Connections() uint64 { return s.connections.Load() }
func (s *RawServer) Requests() uint64    { return s.requests.Load() }

func (s *RawServer) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.connections.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(conn)
		}()
	}
}

func (s *RawServer) handle(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log := s.log.With("listener", "auth", "remote", remote)
	log.Info("client connected")

	_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	request, err := ReadRetailRequest(conn)
	if err != nil {
		if !isTimeout(err) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			log.Warn("authentication request failed", "error", err)
		} else {
			log.Warn("authentication request incomplete", "error", err)
		}
		return
	}

	if err := ValidateRetailRequest(request); err != nil {
		log.Warn("authentication request rejected", "error", err)
		return
	}
	s.requests.Add(1)
	if err := s.recorder.Record("auth", "in", remote, request); err != nil {
		log.Warn("authentication capture failed", "error", err)
	}
	summary := SummarizeRequest(request)
	log.Info("retail authentication request received", "bytes", len(request), "sha256", summary.SHA256, "visible_strings", summary.Strings)

	authRequest, err := ParseRetailAuthRequest(request)
	if err != nil {
		log.Warn("authentication request rejected", "error", err)
		return
	}
	response, details, err := BuildLegacySuccessResponse(authRequest.PlatformKey[:], authRequest.GameID)
	if err != nil {
		log.Error("authentication success response construction failed", "error", err)
		return
	}
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	if _, err := conn.Write(response); err != nil {
		log.Warn("authentication response failed", "error", err)
		return
	}
	if err := s.recorder.Record("auth", "out", remote, response); err != nil {
		log.Warn("authentication capture failed", "error", err)
	}
	log.Info("candidate T5-style authentication success sent",
		"bytes", len(response),
		"response_hex", hex.EncodeToString(response),
		"iv_seed", fmt.Sprintf("0x%08x", details.IVSeed),
		"iv_hex", hex.EncodeToString(details.IV[:]),
		"encrypted_game_ticket_sha256", digestHex(details.EncryptedGameTicket[:]),
		"lsg_ticket_sha256", digestHex(details.LSGTicket[:]),
	)
}

func ReadRetailRequest(reader io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	bodySize := binary.LittleEndian.Uint32(prefix[:])
	if bodySize < minRetailRequestBodySize || bodySize > maxRetailRequestBodySize {
		return nil, fmt.Errorf("unexpected retail authentication body size: %d", bodySize)
	}
	request := make([]byte, 4+bodySize)
	copy(request, prefix[:])
	if _, err := io.ReadFull(reader, request[4:]); err != nil {
		return nil, err
	}
	return request, nil
}

type RetailAuthRequest struct {
	GameID      uint32
	PlatformKey [24]byte
}

func ParseRetailAuthRequest(request []byte) (RetailAuthRequest, error) {
	if err := ValidateRetailRequest(request); err != nil {
		return RetailAuthRequest{}, err
	}
	reader := newLSBBitReader(request[6:])
	if _, err := reader.readBits(1); err != nil {
		return RetailAuthRequest{}, err
	}
	if err := reader.readTypedUint32(); err != nil {
		return RetailAuthRequest{}, fmt.Errorf("read random number: %w", err)
	}
	gameID, err := reader.readTypedUint32Value()
	if err != nil {
		return RetailAuthRequest{}, fmt.Errorf("read game ID: %w", err)
	}
	ticketLength, err := reader.readTypedUint32Value()
	if err != nil {
		return RetailAuthRequest{}, fmt.Errorf("read ticket length: %w", err)
	}
	if ticketLength < 56 || ticketLength > uint32(reader.remainingBits()/8) {
		return RetailAuthRequest{}, fmt.Errorf("invalid authorization ticket length: %d", ticketLength)
	}
	ticket, err := reader.readBytes(int(ticketLength))
	if err != nil {
		return RetailAuthRequest{}, fmt.Errorf("read authorization ticket: %w", err)
	}
	var parsed RetailAuthRequest
	parsed.GameID = gameID
	copy(parsed.PlatformKey[:], ticket[32:56])
	return parsed, nil
}

func SummarizeRequest(request []byte) RequestSummary {
	return RequestSummary{SHA256: digestHex(request), Strings: printableStrings(request, 4)}
}

type lsbBitReader struct {
	data   []byte
	bitPos int
}

func newLSBBitReader(data []byte) *lsbBitReader {
	return &lsbBitReader{data: data}
}

func (r *lsbBitReader) remainingBits() int {
	return len(r.data)*8 - r.bitPos
}

func (r *lsbBitReader) readBits(count int) (uint64, error) {
	if count < 0 || count > 64 || count > r.remainingBits() {
		return 0, io.ErrUnexpectedEOF
	}
	var value uint64
	for bit := 0; bit < count; bit++ {
		value |= uint64((r.data[r.bitPos/8]>>uint(r.bitPos%8))&1) << uint(bit)
		r.bitPos++
	}
	return value, nil
}

func (r *lsbBitReader) readBytes(count int) ([]byte, error) {
	value := make([]byte, count)
	for i := range value {
		encoded, err := r.readBits(8)
		if err != nil {
			return nil, err
		}
		value[i] = byte(encoded)
	}
	return value, nil
}

func (r *lsbBitReader) readTypedUint32() error {
	_, err := r.readTypedUint32Value()
	return err
}

func (r *lsbBitReader) readTypedUint32Value() (uint32, error) {
	dataType, err := r.readBits(5)
	if err != nil {
		return 0, err
	}
	if dataType != 8 {
		return 0, fmt.Errorf("unexpected data type: %d", dataType)
	}
	value, err := r.readBits(32)
	return uint32(value), err
}

func digestHex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func printableStrings(data []byte, minimum int) []string {
	var result []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minimum {
			value := strings.TrimSpace(string(data[start:end]))
			if value != "" {
				result = append(result, value)
			}
		}
		start = -1
	}
	for index, value := range data {
		if value >= 0x20 && value <= 0x7e {
			if start < 0 {
				start = index
			}
			continue
		}
		flush(index)
	}
	flush(len(data))
	if len(result) > 16 {
		return result[:16]
	}
	return result
}

func ValidateRetailRequest(request []byte) error {
	minSize := 4 + minRetailRequestBodySize
	maxSize := 4 + maxRetailRequestBodySize
	if len(request) < minSize || len(request) > maxSize {
		return fmt.Errorf("unexpected retail authentication request size: %d", len(request))
	}
	return nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
