package auth

import (
	"bytes"
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
	mw2GameID                = 0x14a0
	ps3LSGSessionKeyOffset   = 151
	// ps3RPCNKeyMarkerDelta is the distance, in bytes, from the start of the
	// "RPCN" platform-ticket marker back to the 24-byte LSG session key. Verified
	// against runtime tickets: the key validates the client's encrypted LSG
	// records at marker_offset-60, and the layout is stable relative to the
	// marker (the tail shifts as earlier variable-length fields change).
	ps3RPCNKeyMarkerDelta       = 60
	ps3RPCNPlatformTicketMarker = "RPCN"
)

var ObservedRejection = []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x13, 0xc4, 0x05, 0x00, 0x00, 0x00}

type RequestSummary struct {
	SHA256  string
	Strings []string
}

type RawServer struct {
	addr           string
	log            *slog.Logger
	recorder       *capture.Recorder
	readTimeout    time.Duration
	writeTimeout   time.Duration
	connections    atomic.Uint64
	requests       atomic.Uint64
	lsgConnections atomic.Uint64
	lsgFrames      atomic.Uint64
	lsgSessions    *lsgSessionStore
}

func NewRawServer(addr string, log *slog.Logger, recorder *capture.Recorder, readTimeout, writeTimeout time.Duration) *RawServer {
	return &RawServer{
		addr:         addr,
		log:          log,
		recorder:     recorder,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
		lsgSessions:  newLSGSessionStore(),
	}
}

func (s *RawServer) Connections() uint64    { return s.connections.Load() }
func (s *RawServer) Requests() uint64       { return s.requests.Load() }
func (s *RawServer) LSGConnections() uint64 { return s.lsgConnections.Load() }
func (s *RawServer) LSGFrames() uint64      { return s.lsgFrames.Load() }

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
	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		if !isTimeout(err) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			log.Warn("connection prefix failed", "error", err)
		}
		return
	}
	if bodySize := binary.LittleEndian.Uint32(prefix[:]); bodySize < minRetailRequestBodySize && bodySize >= 12 {
		s.handleLSG(conn, remote, prefix)
		return
	}
	request, err := ReadRetailRequest(io.MultiReader(bytes.NewReader(prefix[:]), conn))
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
	if authRequest.GameID != mw2GameID {
		log.Warn("authentication request rejected", "game_id", fmt.Sprintf("0x%08x", authRequest.GameID))
		return
	}
	platformKey := authRequest.Ticket[32:56]
	lsgSessionKey, err := parsePS3LSGSessionKey(authRequest.Ticket)
	if err != nil {
		log.Warn("authentication request rejected", "ticket_bytes", len(authRequest.Ticket), "error", err)
		return
	}
	logTicketKeyDiagnostic(log, authRequest.Ticket, lsgSessionKey)
	response, details, err := BuildLegacySuccessResponse(platformKey, authRequest.GameID)
	if err != nil {
		log.Warn("authentication response generation failed", "error", err)
		return
	}
	s.sessionStore().putWithPendingKey(details.LSGTicket, [24]byte{}, lsgSessionKey)
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	if _, err := conn.Write(response); err != nil {
		log.Warn("authentication response failed", "error", err)
		return
	}
	if err := s.recorder.Record("auth", "out", remote, response); err != nil {
		log.Warn("authentication capture failed", "error", err)
	}
	log.Info("MW2 authentication success generated",
		"bytes", len(response),
		"response_hex", hex.EncodeToString(response),
		"game_id", fmt.Sprintf("0x%08x", authRequest.GameID),
		"session_key_hex", hex.EncodeToString(details.SessionKey[:]),
	)
}

func (s *RawServer) handleLSG(conn net.Conn, remote string, prefix [4]byte) {
	log := s.log.With("listener", "lsg", "remote", remote)
	s.lsgConnections.Add(1)
	log.Info("retail LSG client connected")

	initial, err := readLSGInitialRecord(conn, prefix, RetailRequestSize)
	if err != nil {
		log.Warn("retail LSG initial record incomplete", "error", err)
		return
	}
	if err := s.recordLSGFrame(log, remote, initial); err != nil {
		return
	}
	request, err := parseLSGInitialRecord(initial)
	if err != nil {
		log.Warn("retail LSG authentication rejected", "error", err)
		return
	}
	if request.GameID != 0 && request.GameID != mw2GameID {
		log.Warn("retail LSG authentication rejected", "game_id", fmt.Sprintf("0x%08x", request.GameID))
		return
	}
	storedSession, ok := s.sessionStore().consume(request.Ticket[:])
	if !ok {
		log.Warn("retail LSG authentication rejected", "reason", "unknown or expired ticket")
		return
	}
	session, err := newLSGConnectionWithPendingKey(storedSession.key, storedSession.pendingKey)
	if err != nil {
		log.Warn("retail LSG session setup failed", "error", err)
		return
	}
	if !s.writeLSGResponse(conn, remote, session.helloResponse(), 1, log) {
		return
	}

	for step := 2; ; step++ {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		frame, err := readLSGFrame(conn, 16<<20)
		if err != nil {
			if !isTimeout(err) && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Warn("retail LSG request failed", "step", step, "error", err)
			}
			return
		}
		if err := s.recordLSGFrame(log, remote, frame); err != nil {
			return
		}
		messageType, payload, err := session.decryptRequest(frame)
		if err != nil {
			log.Warn("retail LSG request rejected", "step", step, "error", err)
			session.diagnoseRequest(log, step, frame)
			return
		}
		logLSGRequest(log, step, messageType, payload)
		responseType, responsePayload, handled, reply := handleLSGMessage(session, messageType, payload)
		if !handled {
			// Keep the connection open so the client continues to send the rest
			// of its post-login sequence, letting us observe every unimplemented
			// service/operation instead of tearing down at the first unknown one.
			log.Warn("unimplemented retail LSG request", "step", step, "service_id", messageType, "payload_hex", hex.EncodeToString(payload))
			continue
		}
		if !reply {
			continue
		}
		response, err := session.encryptResponse(responseType, responsePayload)
		if err != nil {
			log.Warn("retail LSG response encryption failed", "step", step, "error", err)
			return
		}
		if !s.writeLSGResponse(conn, remote, response, step, log) {
			return
		}
	}
}

func logLSGRequest(log *slog.Logger, step int, serviceID byte, payload []byte) {
	attrs := []any{
		"step", step,
		"service_id", serviceID,
		"payload_len", len(payload),
		"payload_hex", hex.EncodeToString(payload),
		"visible_strings", printableStrings(payload, 3),
	}
	if len(payload) > 0 {
		operationID := payload[0]
		if operationID == bdTypeU8 && len(payload) >= 2 {
			operationID = payload[1]
		}
		attrs = append(attrs, "operation_id", operationID)
	}
	log.Info("retail LSG service request decrypted", attrs...)
}

func handleLSGMessage(session *lsgConnection, serviceID byte, payload []byte) (byte, []byte, bool, bool) {
	responseType, responsePayload, handled := session.handleTask(serviceID, payload)
	return responseType, responsePayload, handled, handled
}

func (s *RawServer) writeLSGResponse(conn net.Conn, remote string, response []byte, step int, log *slog.Logger) bool {
	_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
	if _, err := conn.Write(response); err != nil {
		log.Warn("retail LSG response failed", "step", step, "error", err)
		return false
	}
	if err := s.recorder.Record("lsg", "out", remote, response); err != nil {
		log.Warn("retail LSG capture failed", "step", step, "error", err)
	}
	log.Info("dynamic retail LSG response sent", "step", step, "bytes", len(response))
	return true
}

func (s *RawServer) sessionStore() *lsgSessionStore {
	if s.lsgSessions == nil {
		s.lsgSessions = newLSGSessionStore()
	}
	return s.lsgSessions
}

func (s *RawServer) recordLSGFrame(log *slog.Logger, remote string, frame []byte) error {
	s.lsgFrames.Add(1)
	if err := s.recorder.Record("lsg", "in", remote, frame); err != nil {
		log.Warn("retail LSG capture failed", "error", err)
		return err
	}
	summary := SummarizeRequest(frame)
	log.Info("retail LSG record received", "bytes", len(frame), "sha256", summary.SHA256, "frame_hex", hex.EncodeToString(frame))
	return nil
}

func readLSGInitialRecord(reader io.Reader, prefix [4]byte, maxPayloadSize uint32) ([]byte, error) {
	var header [12]byte
	copy(header[:4], prefix[:])
	if _, err := io.ReadFull(reader, header[4:]); err != nil {
		return nil, err
	}
	payloadSize := binary.LittleEndian.Uint32(header[8:12])
	if payloadSize == 0 || payloadSize > maxPayloadSize {
		return nil, fmt.Errorf("unexpected retail LSG initial payload size: %d", payloadSize)
	}
	record := make([]byte, 12+payloadSize)
	copy(record, header[:])
	if _, err := io.ReadFull(reader, record[12:]); err != nil {
		return nil, err
	}
	return record, nil
}

func readLSGFrame(reader io.Reader, maxBodySize uint32) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	return readLSGFrameWithPrefix(reader, prefix, maxBodySize)
}

func readLSGFrameWithPrefix(reader io.Reader, prefix [4]byte, maxBodySize uint32) ([]byte, error) {
	bodySize := binary.LittleEndian.Uint32(prefix[:])
	if bodySize == 0 || bodySize > maxBodySize {
		return nil, fmt.Errorf("unexpected retail LSG body size: %d", bodySize)
	}
	frame := make([]byte, 4+bodySize)
	copy(frame, prefix[:])
	if _, err := io.ReadFull(reader, frame[4:]); err != nil {
		return nil, err
	}
	return frame, nil
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
	GameID uint32
	Ticket []byte
}

func parsePS3LSGSessionKey(ticket []byte) ([24]byte, error) {
	var key [24]byte
	offset := ps3LSGSessionKeyOffset
	if marker := bytes.Index(ticket, []byte(ps3RPCNPlatformTicketMarker)); marker >= 0 {
		// RPCN tickets place the LSG session key at a fixed distance before the
		// "RPCN" marker rather than at the retail absolute offset.
		offset = marker - ps3RPCNKeyMarkerDelta
	}
	if offset < 0 || len(ticket) < offset+len(key) {
		return key, fmt.Errorf("authorization ticket is too short for LSG session key at offset %d", offset)
	}
	copy(key[:], ticket[offset:offset+len(key)])
	return key, nil
}

func isAllZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

// logTicketKeyDiagnostic records the raw authorization ticket, the extracted LSG
// session key, and the file offsets of markers/non-zero windows. It helps locate
// where the real 24-byte session key sits inside an RPCN ticket when the
// configured offset yields zeros.
func logTicketKeyDiagnostic(log *slog.Logger, ticket []byte, extractedKey [24]byte) {
	rpcnOffset := -1
	if idx := bytes.Index(ticket, []byte(ps3RPCNPlatformTicketMarker)); idx >= 0 {
		rpcnOffset = idx
	}
	// Identify the byte ranges that are non-zero, to reveal where key-like data lives.
	type span struct {
		Start int `json:"start"`
		End   int `json:"end"`
	}
	var nonZeroSpans []span
	start := -1
	for i := 0; i <= len(ticket); i++ {
		if i < len(ticket) && ticket[i] != 0 {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			nonZeroSpans = append(nonZeroSpans, span{Start: start, End: i})
			start = -1
		}
	}
	log.Info("LSG ticket key diagnostic",
		"ticket_len", len(ticket),
		"ticket_hex", hex.EncodeToString(ticket),
		"extracted_key_hex", hex.EncodeToString(extractedKey[:]),
		"extracted_key_all_zero", isAllZero(extractedKey[:]),
		"rpcn_marker_offset", rpcnOffset,
		"rpcn_key_marker_delta", ps3RPCNKeyMarkerDelta,
		"configured_retail_key_offset", ps3LSGSessionKeyOffset,
		"non_zero_spans", fmt.Sprintf("%+v", nonZeroSpans),
	)
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
	return RetailAuthRequest{GameID: gameID, Ticket: ticket}, nil
}

func SummarizeRequest(request []byte) RequestSummary {
	return RequestSummary{SHA256: digestHex(request), Strings: printableStrings(request, 4)}
}

func responseSessionKey(response []byte) []byte {
	parsed, err := ParseLegacySuccessResponse(response)
	if err != nil {
		return nil
	}
	return append([]byte(nil), parsed.SessionKey[:]...)
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
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
