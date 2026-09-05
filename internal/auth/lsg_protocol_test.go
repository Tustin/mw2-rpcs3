package auth

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/bandwidth"
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
	response, err := session.encryptResponse(lsgTaskReplyType, payload)
	if err != nil {
		t.Fatal(err)
	}
	messageType, decrypted, err := session.decryptResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != lsgTaskReplyType || !bytes.Equal(decrypted[:len(payload)], payload) {
		t.Fatalf("type=%d payload=%x", messageType, decrypted)
	}
	for _, value := range decrypted[len(payload):] {
		if value != 0 {
			t.Fatalf("nonzero LSG padding: %x", decrypted[len(payload):])
		}
	}
}

func TestHandleLSGMessageDispatchesServiceRequest(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	responseType, result, ok, reply := handleLSGMessage(session, bdServiceTitleUtilities, []byte{bdTypeU8, 6})
	if !ok || !reply || responseType != lsgTaskReplyType {
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
	responseType, result, ok, reply := handleLSGMessage(session, bdServiceDML, []byte{bdTypeU8, 2})
	if !ok || !reply || responseType != lsgTaskReplyType {
		t.Fatalf("DML task was not handled: %x", result)
	}
	if !bytes.Contains(result, []byte("US\x00")) || !bytes.Contains(result, []byte("United States\x00")) {
		t.Fatalf("DML result missing expected location fields: %x", result)
	}
}

func TestDecodeObservedLSGStatsTaskOperation(t *testing.T) {
	payload := mustDecodeHex("07c10038010000002800000040e96b8f7bf94413e002")
	operationID, ok := decodeLSGTaskOperation(payload)
	if !ok || operationID != 4 {
		t.Fatalf("stats service=%d operation=%d ok=%v payload=%x", bdServiceStats, operationID, ok, payload)
	}
}

func TestHandleObservedLSGStatsTaskReturnsEmptySuccess(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := mustDecodeHex("07c10038010000002800000040e96b8f7bf94413e002")
	responseType, result, ok, reply := handleLSGMessage(session, bdServiceStats, payload)
	if !ok || !reply || responseType != lsgTaskReplyType {
		t.Fatalf("stats response type=%d payload=%x ok=%v reply=%v", responseType, result, ok, reply)
	}
	if session.lastServiceID != bdServiceStats || session.lastOperationID != 4 {
		t.Fatalf("stats service=%d operation=%d", session.lastServiceID, session.lastOperationID)
	}
	if len(result) != 26 {
		t.Fatalf("stats reply length=%d payload=%x", len(result), result)
	}
	if transaction := binary.LittleEndian.Uint64(result[1:9]); transaction != 0 {
		t.Fatalf("stats transaction=%d", transaction)
	}
	if errorCode := binary.LittleEndian.Uint32(result[10:14]); errorCode != bdErrorNone {
		t.Fatalf("stats error=%d", errorCode)
	}
	if result[14] != bdTypeU8 || result[15] != 4 || result[16] != bdTypeU32 || binary.LittleEndian.Uint32(result[17:21]) != 0 || result[21] != bdTypeU32 || binary.LittleEndian.Uint32(result[22:26]) != 0 {
		t.Fatalf("malformed stats reply=%x", result)
	}
}

func buildPerformanceValuesRequest(performanceType uint32, entityIDs ...uint64) []byte {
	writer := newBDBitWriter()
	writer.writeU8(2)
	writer.writeU32(performanceType)
	for _, entityID := range entityIDs {
		writer.writeU64(entityID)
	}
	return writer.bytes()
}

func TestParseCapturedPerformanceValuesRequest(t *testing.T) {
	payload := mustDecodeHex("87000200000050fadae35e3ed104b800080808")
	performanceType, entityIDs, valid := parsePerformanceValuesRequest(payload)
	if !valid || performanceType != 0 || len(entityIDs) != 1 || entityIDs[0] != 0xb804d13e5ee3dafa {
		t.Fatalf("valid=%v performance_type=%d entities=%x", valid, performanceType, entityIDs)
	}
}

func TestHandlePerformanceValuesReturnsSessionBackedValues(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	entityIDs := []uint64{0xb804d13e5ee3dafa, 0x1cef2987c7049084}
	ownerID := uint64(0x1122334455667788)
	session.connectionID = ownerID
	session.entityID = entityIDs[0]
	_, createReply, handled := session.handleMatchmakingTask(buildMW2SessionObjectRequest(bdMatchmakingCreateSession))
	if !handled || !session.lastTaskSupported {
		t.Fatalf("create handled=%v supported=%v reply=%x", handled, session.lastTaskSupported, createReply)
	}
	created := session.lastMatchmakingSessions[0]
	if created.ownerID != ownerID || created.entityID != entityIDs[0] {
		t.Fatalf("created owner=%x entity=%x", created.ownerID, created.entityID)
	}
	payload := buildPerformanceValuesRequest(0, entityIDs...)
	responseType, result, ok, reply := handleLSGMessage(session, bdServicePerformance, payload)
	if !ok || !reply || responseType != lsgTaskReplyType {
		t.Fatalf("performance response type=%d payload=%x ok=%v reply=%v", responseType, result, ok, reply)
	}
	if !session.lastTaskSupported || session.lastServiceID != bdServicePerformance || session.lastOperationID != 2 {
		t.Fatalf("supported=%v service=%d operation=%d", session.lastTaskSupported, session.lastServiceID, session.lastOperationID)
	}
	reader, err := newBDTaskReplyReader(result)
	if err != nil {
		t.Fatal(err)
	}
	if transactionID, err := reader.readU64(); err != nil || transactionID != 1 {
		t.Fatalf("transaction=%d err=%v", transactionID, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("error=%d err=%v", errorCode, err)
	}
	if operationID, err := reader.readU8(); err != nil || operationID != 2 {
		t.Fatalf("operation=%d err=%v", operationID, err)
	}
	if count, err := reader.readU32(); err != nil || count != uint32(len(entityIDs)) {
		t.Fatalf("count=%d want=%d err=%v", count, len(entityIDs), err)
	}
	for index, entityID := range entityIDs {
		status, err := reader.bits.readBits(32)
		if err != nil || status != 0 {
			t.Fatalf("status=%d err=%v", status, err)
		}
		if got, err := reader.readU64(); err != nil || got != entityID {
			t.Fatalf("entity=%016x want=%016x err=%v", got, entityID, err)
		}
		var valueBytes [4]byte
		for i := range valueBytes {
			value, err := reader.bits.readBits(8)
			if err != nil {
				t.Fatalf("performance byte %d err=%v", i, err)
			}
			valueBytes[i] = byte(value)
		}
		want := uint32(0)
		if index == 0 {
			want = 1
		}
		if value := binary.BigEndian.Uint32(valueBytes[:]); value != want {
			t.Fatalf("performance=%d want=%d bytes=%x", value, want, valueBytes)
		}
	}
}

func TestHandleMalformedPerformanceValuesReturnsServiceError(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := buildPerformanceValuesRequest(0, 0xb804d13e5ee3dafa)
	payload = payload[:len(payload)-1]
	responseType, result, ok, reply := handleLSGMessage(session, bdServicePerformance, payload)
	if !ok || !reply || responseType != lsgTaskReplyType {
		t.Fatalf("performance response type=%d payload=%x ok=%v reply=%v", responseType, result, ok, reply)
	}
	if session.lastTaskSupported {
		t.Fatal("malformed performance task was marked supported")
	}
	reader, err := newBDTaskReplyReader(result)
	if err != nil {
		t.Fatal(err)
	}
	if transactionID, err := reader.readU64(); err != nil || transactionID != 0 {
		t.Fatalf("transaction=%d err=%v", transactionID, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorServiceNotAvailable {
		t.Fatalf("performance error=%d err=%v payload=%x", errorCode, err, result)
	}
	if operationID, err := reader.readU8(); err != nil || operationID != 2 {
		t.Fatalf("operation=%d err=%v", operationID, err)
	}
}

func TestHandleObservedLSGBandwidthUsesServiceTaskReply(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	session.bandwidthIPv4 = [4]byte{192, 0, 2, 25}
	session.bandwidthPort = 3074
	session.bandwidthConfigured = true
	session.bandwidthMeasurementKey = "client-a"
	session.bandwidthMeasurements = bandwidth.NewStore()
	// Exact decrypted core from the prior live RPCS3 run. Unlike normal tasks,
	// bandwidth uses an untyped raw operation byte.
	payload := mustDecodeHex("010000000000724c3800000000000dcd40")
	responseType, result, ok, reply := handleLSGMessage(session, bdServiceBandwidth, payload)
	if !ok || !reply || responseType != lsgServiceTaskReplyType {
		t.Fatalf("bandwidth response type=%d payload=%x ok=%v reply=%v", responseType, result, ok, reply)
	}
	if !session.lastTaskSupported || session.lastServiceID != bdServiceBandwidth || session.lastOperationID != 1 {
		t.Fatalf("supported=%v service=%d operation=%d", session.lastTaskSupported, session.lastServiceID, session.lastOperationID)
	}
	want := mustDecodeHex(
		"0000000000000000" +
			"00" +
			"00020000" +
			"05000000" +
			"f4010000" +
			"d0070000" +
			"10270000" +
			"88130000" +
			"f4010000" +
			"020c" +
			"c0000219" +
			"0001020304050607",
	)
	if !bytes.Equal(result, want) {
		t.Fatalf("malformed bandwidth request reply=%x want=%x", result, want)
	}
	frame, err := session.encryptResponse(responseType, result)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 65 {
		t.Fatalf("bandwidth request wire length=%d want=65", len(frame))
	}

	receivedAt := time.Unix(1_700_000_000, 0)
	for sequence := uint32(0); sequence < 5; sequence++ {
		session.bandwidthMeasurements.Record("client-a", sequence, 512, receivedAt.Add(time.Duration(sequence)*500*time.Millisecond))
	}
	finalizePayload := append([]byte{1}, make([]byte, 20)...)
	responseType, result, ok, reply = handleLSGMessage(session, bdServiceBandwidth, finalizePayload)
	if !ok || !reply || responseType != lsgServiceTaskReplyType {
		t.Fatalf("bandwidth finalize response type=%d payload=%x ok=%v reply=%v", responseType, result, ok, reply)
	}
	if session.lastBandwidthPhase != "finalize" || len(result) != 29 || result[8] != 0 {
		t.Fatalf("malformed bandwidth finalize reply phase=%q payload=%x", session.lastBandwidthPhase, result)
	}
	wantResults := []uint32{2560, 2000, 2, 0, 4}
	for index, want := range wantResults {
		if got := binary.LittleEndian.Uint32(result[9+index*4:]); got != want {
			t.Fatalf("bandwidth result[%d]=%d want=%d payload=%x", index, got, want, result)
		}
	}
	frame, err = session.encryptResponse(responseType, result)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != 49 {
		t.Fatalf("bandwidth finalize wire length=%d want=49", len(frame))
	}
}

func TestHandleUnknownLSGTaskReturnsErrorAndMarksUnsupported(t *testing.T) {
	session, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte{0x47, 0x0f}
	const unknownService = byte(99)
	responseType, result, ok, reply := handleLSGMessage(session, unknownService, payload)
	if !ok || !reply || responseType != lsgTaskReplyType {
		t.Fatalf("unknown task response type=%d payload=%x ok=%v reply=%v", responseType, result, ok, reply)
	}
	if session.lastTaskSupported {
		t.Fatal("unknown service task was marked supported")
	}
	if session.lastServiceID != unknownService || session.lastOperationID != 61 {
		t.Fatalf("service=%d operation=%d", session.lastServiceID, session.lastOperationID)
	}
	if errorCode := binary.LittleEndian.Uint32(result[10:14]); errorCode != bdErrorServiceNotAvailable {
		t.Fatalf("error=%d payload=%x", errorCode, result)
	}
}
