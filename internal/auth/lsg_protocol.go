package auth

import (
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"
)

const (
	lsgInitialServiceType   = 7
	lsgTaskReplyType        = 1
	lsgConnectionType       = 4
	lsgServiceTaskReplyType = 5
	lsgMaxSessions          = 64
)

type lsgStoredSession struct {
	key        [24]byte
	pendingKey [24]byte
	created    time.Time
}

type lsgSessionStore struct {
	mu       sync.Mutex
	sessions map[[24]byte]lsgStoredSession
}

func newLSGSessionStore() *lsgSessionStore {
	return &lsgSessionStore{sessions: make(map[[24]byte]lsgStoredSession)}
}

func (s *lsgSessionStore) put(ticket [legacyTicketLen]byte, key [24]byte) {
	s.putWithPendingKey(ticket, key, key)
}

func (s *lsgSessionStore) putWithPendingKey(ticket [legacyTicketLen]byte, key [24]byte, pendingKey [24]byte) {
	var ticketID [24]byte
	copy(ticketID[:], ticket[:len(ticketID)])
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= lsgMaxSessions {
		var oldestID [24]byte
		var oldestTime time.Time
		for candidate, session := range s.sessions {
			if oldestTime.IsZero() || session.created.Before(oldestTime) {
				oldestID = candidate
				oldestTime = session.created
			}
		}
		delete(s.sessions, oldestID)
	}
	s.sessions[ticketID] = lsgStoredSession{key: key, pendingKey: pendingKey, created: time.Now()}
}

func (s *lsgSessionStore) consume(ticket []byte) (lsgStoredSession, bool) {
	var ticketID [24]byte
	if len(ticket) < len(ticketID) {
		return lsgStoredSession{}, false
	}
	copy(ticketID[:], ticket[:len(ticketID)])
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[ticketID]
	if ok {
		delete(s.sessions, ticketID)
	}
	return session, ok
}

type lsgConnection struct {
	key             [24]byte
	pendingKey      [24]byte
	connectionID    uint64
	requestIV       uint32
	responseIV      uint32
	lastServiceID   byte
	lastOperationID byte
}

type lsgInitialRequest struct {
	GameID       uint32
	RandomNumber uint32
	Ticket       [legacyTicketLen]byte
}

func parseLSGInitialRecord(record []byte) (lsgInitialRequest, error) {
	if len(record) < 14 {
		return lsgInitialRequest{}, fmt.Errorf("initial LSG record too short: %d", len(record))
	}
	outerLength := binary.LittleEndian.Uint32(record[:4])
	standardOuterLength := uint32(len(record) - 4)
	retailOuterLength := uint32(len(record) + 28)
	if outerLength != standardOuterLength && outerLength != retailOuterLength {
		return lsgInitialRequest{}, fmt.Errorf("initial LSG outer length is %d, expected %d or %d", outerLength, standardOuterLength, retailOuterLength)
	}
	if record[4] != 0xff {
		return lsgInitialRequest{}, fmt.Errorf("unexpected initial LSG envelope type: %02x", record[4])
	}
	innerLength := binary.LittleEndian.Uint32(record[8:12])
	if int(innerLength) != len(record)-12 {
		return lsgInitialRequest{}, fmt.Errorf("initial LSG inner length is %d, got %d", innerLength, len(record)-12)
	}
	if record[12] != 0 || record[13] != lsgInitialServiceType {
		return lsgInitialRequest{}, fmt.Errorf("unexpected initial LSG type: %02x%02x", record[12], record[13])
	}
	reader := newLSBBitReader(record[14:])
	initial, err := reader.readBits(1)
	if err != nil || initial == 0 {
		return lsgInitialRequest{}, fmt.Errorf("invalid initial LSG flag")
	}
	gameID, err := reader.readTypedUint32Value()
	if err != nil {
		return lsgInitialRequest{}, fmt.Errorf("read LSG game ID: %w", err)
	}
	randomNumber, err := reader.readTypedUint32Value()
	if err != nil {
		return lsgInitialRequest{}, fmt.Errorf("read LSG random number: %w", err)
	}
	ticket, err := reader.readBytes(legacyTicketLen)
	if err != nil {
		return lsgInitialRequest{}, fmt.Errorf("read LSG ticket: %w", err)
	}
	var request lsgInitialRequest
	request.GameID = gameID
	request.RandomNumber = randomNumber
	copy(request.Ticket[:], ticket)
	return request, nil
}

func newLSGConnection(key [24]byte) (*lsgConnection, error) {
	return newLSGConnectionWithPendingKey(key, key)
}

func newLSGConnectionWithPendingKey(key, pendingKey [24]byte) (*lsgConnection, error) {
	if _, err := des.NewTripleDESCipher(key[:]); err != nil {
		return nil, fmt.Errorf("create LSG 3DES cipher: %w", err)
	}
	if _, err := des.NewTripleDESCipher(pendingKey[:]); err != nil {
		return nil, fmt.Errorf("create pending LSG 3DES cipher: %w", err)
	}
	connection := &lsgConnection{key: key, pendingKey: pendingKey}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, fmt.Errorf("generate LSG connection state: %w", err)
	}
	connection.connectionID = binary.LittleEndian.Uint64(random[:8])
	connection.responseIV = binary.LittleEndian.Uint32(random[8:])
	return connection, nil
}

func (c *lsgConnection) helloResponse() []byte {
	payload := newLSBBitWriter(5 + 64)
	for bit := 0; bit < 5; bit++ {
		payload.writeBit(lsgConnectionType&(1<<bit) != 0)
	}
	var encodedID [8]byte
	binary.LittleEndian.PutUint64(encodedID[:], c.connectionID)
	payload.writeBytes(encodedID[:])
	response := make([]byte, 5+len(payload.bytes()))
	binary.LittleEndian.PutUint32(response[:4], uint32(len(response)-4))
	response[4] = 0
	copy(response[5:], payload.bytes())
	return response
}

func (c *lsgConnection) decryptRequest(frame []byte) (byte, []byte, error) {
	decrypted, err := DecryptLSGRecord(frame, c.key[:])
	if err != nil {
		return 0, nil, err
	}
	if !decrypted.Encrypted {
		return 0, nil, fmt.Errorf("expected encrypted LSG request")
	}
	if !decrypted.HMACValid && c.pendingKey != c.key {
		pending, pendingErr := DecryptLSGRecord(frame, c.pendingKey[:])
		if pendingErr == nil && pending.HMACValid {
			c.key = c.pendingKey
			decrypted = pending
		}
	}
	if !decrypted.HMACValid {
		return 0, nil, fmt.Errorf("invalid LSG request HMAC")
	}
	c.requestIV = decrypted.IVSeed
	return decrypted.MessageType, append([]byte(nil), decrypted.Plaintext[5:]...), nil
}

// diagnoseRequest runs HMAC-scope diagnostics against both the active and the
// pending session keys. It is used only for logging when decryptRequest fails.
func (c *lsgConnection) diagnoseRequest(log *slog.Logger, step int, frame []byte) {
	keys := []struct {
		name string
		key  [24]byte
	}{{"active", c.key}}
	if c.pendingKey != c.key {
		keys = append(keys, struct {
			name string
			key  [24]byte
		}{"pending", c.pendingKey})
	}
	for _, k := range keys {
		stored, plaintext, candidates, err := DiagnoseLSGRecordHMAC(frame, k.key[:])
		if err != nil {
			log.Warn("LSG HMAC diagnostic failed", "step", step, "key", k.name, "error", err)
			continue
		}
		matches := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			if candidate.Matches {
				matches = append(matches, candidate.Name)
			}
		}
		messageType := byte(0)
		if len(plaintext) >= 5 {
			messageType = plaintext[4]
		}
		log.Warn("LSG HMAC diagnostic",
			"step", step,
			"key", k.name,
			"key_hex", hex.EncodeToString(k.key[:]),
			"stored_hmac", fmt.Sprintf("0x%08x", stored),
			"message_type", messageType,
			"plaintext_hex", hex.EncodeToString(plaintext),
			"matching_scopes", matches,
		)
	}
}

func (c *lsgConnection) encryptResponse(messageType byte, payload []byte) ([]byte, error) {
	response, err := EncryptLSGRecord(messageType, payload, c.responseIV, c.key[:])
	if err != nil {
		return nil, err
	}
	c.responseIV++
	return response, nil
}

func (c *lsgConnection) decryptResponse(frame []byte) (byte, []byte, error) {
	decrypted, err := DecryptLSGRecord(frame, c.key[:])
	if err != nil {
		return 0, nil, err
	}
	if !decrypted.Encrypted || !decrypted.HMACValid {
		return 0, nil, fmt.Errorf("invalid encrypted LSG response")
	}
	return decrypted.MessageType, append([]byte(nil), decrypted.Plaintext[5:]...), nil
}

const (
	bdTypeBool   = 0x01
	bdTypeU8     = 0x03
	bdTypeU16    = 0x06
	bdTypeU32    = 0x08
	bdTypeU64    = 0x0a
	bdTypeF32    = 0x0d
	bdTypeString = 0x10

	bdServiceStorage        = 10
	bdServiceTitleUtilities = 12
	bdServiceBandwidth      = 18
	bdServiceDML            = 27

	bdErrorNone                = 0
	bdErrorServiceNotAvailable = 108
	bdErrorNoFile              = 1000
)

type bdByteWriter struct {
	data []byte
}

func (w *bdByteWriter) writeType(value byte) {
	w.data = append(w.data, value)
}

func (w *bdByteWriter) writeU8(value byte) {
	w.writeType(bdTypeU8)
	w.data = append(w.data, value)
}

func (w *bdByteWriter) writeU16(value uint16) {
	w.writeType(bdTypeU16)
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	w.data = append(w.data, encoded[:]...)
}

func (w *bdByteWriter) writeU32(value uint32) {
	w.writeType(bdTypeU32)
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	w.data = append(w.data, encoded[:]...)
}

func (w *bdByteWriter) writeU64(value uint64) {
	w.writeType(bdTypeU64)
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	w.data = append(w.data, encoded[:]...)
}

func (w *bdByteWriter) writeF32(value float32) {
	w.writeType(bdTypeF32)
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], math.Float32bits(value))
	w.data = append(w.data, encoded[:]...)
}

func (w *bdByteWriter) writeString(value string) {
	w.writeType(bdTypeString)
	w.data = append(w.data, value...)
	w.data = append(w.data, 0)
}

func (c *lsgConnection) taskReply(operationID byte, errorCode uint32, results func(*bdByteWriter)) []byte {
	writer := &bdByteWriter{}
	writer.writeU64(0)
	writer.writeU32(errorCode)
	writer.writeU8(operationID)
	resultCount := uint32(0)
	if results != nil {
		resultCount = 1
	}
	writer.writeU32(resultCount)
	writer.writeU32(resultCount)
	if results != nil {
		results(writer)
	}
	return writer.data
}

func (c *lsgConnection) handleTask(serviceID byte, payload []byte) (byte, []byte, bool) {
	if len(payload) == 0 {
		return 0, nil, false
	}
	operationID := payload[0]
	if operationID == bdTypeU8 && len(payload) >= 2 {
		operationID = payload[1]
	}
	c.lastServiceID = serviceID
	c.lastOperationID = operationID

	switch {
	case serviceID == bdServiceTitleUtilities && operationID == 6:
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorNone, func(writer *bdByteWriter) {
			writer.writeU32(uint32(time.Now().Unix()))
		}), true
	case serviceID == bdServiceDML && operationID == 2:
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorNone, func(writer *bdByteWriter) {
			writer.writeString("US")
			writer.writeString("United States")
			writer.writeString("")
			writer.writeString("")
			writer.writeF32(0)
			writer.writeF32(0)
		}), true
	case serviceID == bdServiceDML && operationID == 3:
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorNone, func(writer *bdByteWriter) {
			writer.writeString("US")
			writer.writeString("United States")
			writer.writeString("")
			writer.writeString("")
			writer.writeF32(0)
			writer.writeF32(0)
			writer.writeU32(0)
			writer.writeU32(0)
			writer.writeU32(0)
			writer.writeU32(0)
		}), true
	case serviceID == bdServiceBandwidth && operationID == 1:
		response := make([]byte, 11)
		response[8] = 1
		binary.LittleEndian.PutUint16(response[9:], bdErrorServiceNotAvailable)
		return lsgServiceTaskReplyType, response, true
	case serviceID == bdServiceStorage:
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorNoFile, nil), true
	default:
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
	}
}
