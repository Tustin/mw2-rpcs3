package auth

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseLSGInitialRecord(t *testing.T) {
	var ticket [legacyTicketLen]byte
	copy(ticket[:24], candidateSessionKey[:])
	record := buildLSGInitialRecord(mw2GameID, 0x9f08a100, ticket)
	parsed, err := parseLSGInitialRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.GameID != mw2GameID || parsed.RandomNumber != 0x9f08a100 {
		t.Fatalf("game=%08x random=%08x", parsed.GameID, parsed.RandomNumber)
	}
	if !bytes.Equal(parsed.Ticket[:], ticket[:]) {
		t.Fatal("LSG ticket mismatch")
	}
}

func TestParseCapturedRetailLSGInitialRecord(t *testing.T) {
	record := mustDecodeHex("b4000000ffff00008c0000000007112805000042113e2d03b95caa2cd10db9269e48e76a14e876fc1af3e4da0bb8e7d946fdcab0d66895649b765d038575223dc67fdbddd47dafb5ec2a1f9fc785bbf449d0d9670616113138663b9c645c52d8d6db7bc6a436550e623644fc3b674325fce0d6373bed997e50b9daf953009edba3d7d33c7b63dba7b8a20b76e98ae17caeb0f92102506f06")
	parsed, err := parseLSGInitialRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.GameID != mw2GameID || parsed.RandomNumber != 0x65a7c228 {
		t.Fatalf("game=%08x random=%08x", parsed.GameID, parsed.RandomNumber)
	}
}

func TestLSGSessionStoreConsumesTicketsOnce(t *testing.T) {
	store := newLSGSessionStore()
	var ticket [legacyTicketLen]byte
	copy(ticket[:24], candidateSessionKey[:])
	cryptoKey := [24]byte{1, 2, 3, 4}
	store.put(ticket, cryptoKey)
	stored, ok := store.consume(ticket[:])
	if !ok || stored.key != cryptoKey || stored.pendingKey != cryptoKey {
		t.Fatalf("stored=%+v ok=%v", stored, ok)
	}
	if _, ok := store.consume(ticket[:]); ok {
		t.Fatal("ticket was accepted twice")
	}
}

func TestLSGEncryptedResponseRoundTrip(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 31)
	payload[0] = bdTypeU64
	binary.LittleEndian.PutUint64(payload[1:9], 0x12345678)
	payload[9] = bdTypeU32
	binary.LittleEndian.PutUint32(payload[10:14], bdErrorNone)
	response, err := session.encryptResponse(lsgResultReplyType, payload)
	if err != nil {
		t.Fatal(err)
	}
	messageType, decrypted, err := session.decryptResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != lsgResultReplyType || !bytes.Equal(decrypted[:len(payload)], payload) {
		t.Fatalf("type=%d payload=%x", messageType, decrypted)
	}
	for _, value := range decrypted[len(payload):] {
		if value != 0 {
			t.Fatalf("nonzero LSG padding: %x", decrypted[len(payload):])
		}
	}
}

func TestHandleLSGMessageConnectionAndResult(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	connectionID := uint64(0xb9398889437679d9)
	connectionPayload := make([]byte, 9)
	connectionPayload[0] = bdTypeU64
	binary.LittleEndian.PutUint64(connectionPayload[1:], connectionID)
	responseType, responsePayload, ok, reply := handleLSGMessage(session, lsgConnectionIDType, connectionPayload)
	if !ok || reply || responseType != 0 || responsePayload != nil || !session.loggedIn {
		t.Fatalf("connection-ID handling type=%d payload=%x ok=%v reply=%v", responseType, responsePayload, ok, reply)
	}
	if session.connectionID != connectionID {
		t.Fatalf("connection ID=%016x", session.connectionID)
	}
	responseType, result, ok, reply := handleLSGMessage(session, lsgResultReplyType, []byte{bdServiceTitleUtilities, bdTypeU8, 6})
	if !ok || !reply || responseType != lsgResultReplyType {
		t.Fatalf("result payload=%x", result)
	}
	if len(result) != 31 || result[0] != bdTypeU64 || result[9] != bdTypeU32 || result[14] != bdTypeU8 || result[16] != bdTypeU32 || result[21] != bdTypeU32 || result[26] != bdTypeU32 {
		t.Fatalf("malformed typed task reply=%x", result)
	}
	if binary.LittleEndian.Uint32(result[17:21]) != 1 || binary.LittleEndian.Uint32(result[22:26]) != 1 {
		t.Fatalf("unexpected result counts=%x", result)
	}
}

func TestHandleLSGDMLTaskReply(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	session.loggedIn = true
	responseType, result, ok, reply := handleLSGMessage(session, lsgResultReplyType, []byte{bdServiceDML, bdTypeU8, 2})
	if !ok || !reply || responseType != lsgResultReplyType {
		t.Fatalf("DML task was not handled: %x", result)
	}
	if !bytes.Contains(result, []byte("US\x00")) || !bytes.Contains(result, []byte("United States\x00")) {
		t.Fatalf("DML result missing expected location fields: %x", result)
	}
}

func TestHandleLSGRejectsTaskBeforeLogin(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok, _ := handleLSGMessage(session, lsgResultReplyType, []byte{bdServiceStorage, bdTypeU8, 3}); ok {
		t.Fatal("pre-login task was accepted")
	}
}

func TestHandleLSGConnectionIDMarksLogin(t *testing.T) {
	// The real client connection-ID/registration record is a fixed structure
	// beginning with bdTypeBool (0x01), not a tagged u64. The handler must accept
	// it, mark the session logged in, and send no reply.
	realPayload := mustDecodeHex("01000100000000000000000000000000000000")
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	responseType, responsePayload, ok, reply := handleLSGMessage(session, lsgConnectionIDType, realPayload)
	if !ok {
		t.Fatal("real connection-ID notification was rejected")
	}
	if reply {
		t.Fatal("connection-ID notification must not produce a reply")
	}
	if responseType != 0 || responsePayload != nil {
		t.Fatalf("unexpected response: type=%d payload=%x", responseType, responsePayload)
	}
	if !session.loggedIn {
		t.Fatal("session was not marked logged in")
	}
}

func TestHandleLSGConnectionIDExtractsTaggedU64(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 9)
	payload[0] = bdTypeU64
	binary.LittleEndian.PutUint64(payload[1:], 0xb9398889437679d9)
	if _, _, ok, _ := handleLSGMessage(session, lsgConnectionIDType, payload); !ok {
		t.Fatal("tagged connection-ID notification was rejected")
	}
	if session.connectionID != 0xb9398889437679d9 {
		t.Fatalf("connection ID not extracted: 0x%016x", session.connectionID)
	}
}
