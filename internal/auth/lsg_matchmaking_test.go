package auth

import (
	"bytes"
	"encoding/hex"
	"math"
	"testing"
)

func buildMW2FindSessionsRequest() []byte {
	return buildMW2FindSessionsRequestWithSearch(
		2,
		50,
		mw2MatchmakingSearch{
			gameType:          math.MaxInt32,
			gameMode:          math.MaxInt32,
			netcodeVersion:    math.MaxInt32,
			mapPackFlags:      math.MaxInt32,
			playlistVersion:   math.MaxInt32,
			requiredFreeSlots: math.MaxInt32,
		},
	)
}

func buildMW2FindSessionsRequestWithSearch(
	queryType int32,
	maxResults int32,
	search mw2MatchmakingSearch,
) []byte {
	bits := newLSBBitWriter(0)
	bits.writeBit(true)
	writer := &bdBitWriter{bits: bits}
	writer.writeU8(bdMatchmakingFindSessions)
	writer.writeU8(0)
	writer.writeI32(queryType)
	writer.writeI32(maxResults)
	writer.writeI32(search.gameType)
	writer.writeI32(search.gameMode)
	writer.writeI32(search.netcodeVersion)
	writer.writeI32(search.mapPackFlags)
	writer.writeI32(search.playlistVersion)
	writer.writeI32(search.requiredFreeSlots)
	writer.writeI32(search.performance)
	bits.writeBits(0, 8)
	bits.writeBits(0, 8)
	bits.writeBits(0, 5)
	return writer.bytes()
}

// Retained for full-flow tests that construct raw positional fixtures.
func buildMW2FindSessionsRequestWithValues(
	queryType int32,
	maxResults int32,
	values [6]int32,
	performance int32,
) []byte {
	return buildMW2FindSessionsRequestWithSearch(
		queryType,
		maxResults,
		mw2MatchmakingSearch{
			gameType:          values[0],
			gameMode:          values[1],
			netcodeVersion:    values[2],
			mapPackFlags:      values[3],
			playlistVersion:   values[4],
			requiredFreeSlots: values[5],
			performance:       performance,
		},
	)
}

func buildMW2SessionObjectRequest(operationID byte) []byte {
	return buildMW2SessionObjectRequestWithValues(
		operationID,
		bytes.Repeat([]byte{0x11}, mw2MatchmakingCommonAddressSize),
		bytes.Repeat([]byte{0x22}, mw2MatchmakingSessionIDSize),
		bytes.Repeat([]byte{0x33}, mw2MatchmakingSecurityKeySize),
		[4]int32{18, 1, 0, 0},
		[9]int32{1, 2, 3, 4, 5, 6, 7, 8, 9},
	)
}

func buildMW2SessionObjectRequestWithValues(
	operationID byte,
	commonAddress []byte,
	sessionID []byte,
	securityKey []byte,
	counts [4]int32,
	attributes [9]int32,
) []byte {
	bits := newLSBBitWriter(0)
	bits.writeBit(true)
	writer := &bdBitWriter{bits: bits}
	writer.writeU8(operationID)
	writer.writeU8(0)
	writer.writeBlob(commonAddress)
	writer.writeBlob(sessionID)
	writer.writeBlob(securityKey)
	for _, count := range counts {
		writer.writeI32(count)
	}
	for _, attribute := range attributes {
		writer.writeI32(attribute)
	}
	bits.writeBits(0, 8)
	bits.writeBits(0, 8)
	bits.writeBits(0, 5)
	return writer.bytes()
}

func buildMW2SessionIDRequest(operationID byte) []byte {
	return buildMW2SessionIDRequestWithValue(
		operationID,
		bytes.Repeat([]byte{0x44}, mw2MatchmakingSessionIDSize),
	)
}

func buildMW2SessionIDRequestWithValue(operationID byte, sessionID []byte) []byte {
	bits := newLSBBitWriter(0)
	bits.writeBit(true)
	writer := &bdBitWriter{bits: bits}
	writer.writeU8(operationID)
	writer.writeU8(0)
	writer.writeBlob(sessionID)
	bits.writeBits(0, 5)
	return writer.bytes()
}

func TestParseRecoveredMW2FindSessionsRequest(t *testing.T) {
	payload := buildMW2FindSessionsRequest()
	request, err := parseMW2MatchmakingRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !request.isRetailPublicSearch() {
		t.Fatalf("request does not match retail public search: %+v payload=%x", request, payload)
	}
	if request.operationID != bdMatchmakingFindSessions ||
		request.reserved != 0 ||
		request.queryType != 2 ||
		request.maxResults != 50 ||
		request.search.performance != 0 {
		t.Fatalf("request=%+v", request)
	}
	if request.search != (mw2MatchmakingSearch{
		gameType:          math.MaxInt32,
		gameMode:          math.MaxInt32,
		netcodeVersion:    math.MaxInt32,
		mapPackFlags:      math.MaxInt32,
		playlistVersion:   math.MaxInt32,
		requiredFreeSlots: math.MaxInt32,
	}) {
		t.Fatalf("search=%+v", request.search)
	}
}

func TestMW2FindSessionsRequestMatchesRecoveredGoldenBits(t *testing.T) {
	// Golden bytes independently follow the serializers at 0x003e16a0,
	// 0x003de268, 0x00325850, and the task wrapper at 0x003e6f60.
	want, err := hex.DecodeString("47c100380200000047060000e0fcffffff9dffffffbff3ffffff77feffffffceffffffdff9ffffff3b00000000000000")
	if err != nil {
		t.Fatal(err)
	}
	got := buildMW2FindSessionsRequest()
	if !bytes.Equal(got, want) {
		t.Fatalf("find-sessions request=%x want=%x", got, want)
	}
}

func TestMW2FindSessionsPreservesRecoveredSearchValues(t *testing.T) {
	search := mw2MatchmakingSearch{
		gameType:          1,
		gameMode:          2,
		netcodeVersion:    3,
		mapPackFlags:      4,
		playlistVersion:   5,
		requiredFreeSlots: 6,
		performance:       7,
	}
	payload := buildMW2FindSessionsRequestWithSearch(
		2,
		50,
		search,
	)
	want, err := hex.DecodeString("47c100380200000047060000e0040000001c010000803300000070080000004e010000c0310000003807000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("live-value query=%x want=%x", payload, want)
	}
	request, err := parseMW2MatchmakingRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !request.isRetailPublicSearch() {
		t.Fatalf("rejected valid type-2 query: %+v", request)
	}
	if request.search != search {
		t.Fatalf("query values were not preserved: %+v", request)
	}
}

func TestParseRecoveredMW2CreateAndUpdateRequests(t *testing.T) {
	for _, operationID := range []byte{bdMatchmakingCreateSession, bdMatchmakingUpdateSession} {
		request, err := parseMW2MatchmakingRequest(buildMW2SessionObjectRequest(operationID))
		if err != nil {
			t.Fatalf("operation %d: %v", operationID, err)
		}
		if request.operationID != operationID ||
			len(request.info.commonAddress) != mw2MatchmakingCommonAddressSize ||
			len(request.info.sessionID) != mw2MatchmakingSessionIDSize ||
			len(request.info.securityKey) != mw2MatchmakingSecurityKeySize ||
			request.info.openPublic != 18 ||
			request.info.filledPublic != 1 ||
			request.info.openPrivate != 0 ||
			request.info.filledPrivate != 0 ||
			request.info.attributes != [9]int32{1, 2, 3, 4, 5, 6, 7, 8, 9} {
			t.Fatalf("operation %d request=%+v", operationID, request)
		}
	}
}

func TestParseRecoveredMW2DeleteAndFindByIDRequests(t *testing.T) {
	for _, operationID := range []byte{bdMatchmakingDeleteSession, bdMatchmakingFindByID} {
		request, err := parseMW2MatchmakingRequest(buildMW2SessionIDRequest(operationID))
		if err != nil {
			t.Fatalf("operation %d: %v", operationID, err)
		}
		if request.operationID != operationID ||
			!bytes.Equal(request.sessionID, bytes.Repeat([]byte{0x44}, mw2MatchmakingSessionIDSize)) {
			t.Fatalf("operation %d request=%+v", operationID, request)
		}
	}
}

func TestMW2SessionMutationRequestsMatchRecoveredGoldenBits(t *testing.T) {
	goldens := []struct {
		operationID byte
		build       func(byte) []byte
		encoded     string
	}{
		{
			bdMatchmakingCreateSession,
			buildMW2SessionObjectRequest,
			"47c00098280300002022222222222222222222222222222222222222222222222262220400000011111111111111918920000000666666666666666666666666666666668e040000c009000000380000000007000000e0040000001c010000803300000070080000004e010000c031000000380700000007010000e024000000000000",
		},
		{
			bdMatchmakingUpdateSession,
			buildMW2SessionObjectRequest,
			"87c00098280300002022222222222222222222222222222222222222222222222262220400000011111111111111918920000000666666666666666666666666666666668e040000c009000000380000000007000000e0040000001c010000803300000070080000004e010000c031000000380700000007010000e024000000000000",
		},
		{
			bdMatchmakingDeleteSession,
			buildMW2SessionIDRequest,
			"c7c000980801000080888888888888880800",
		},
		{
			bdMatchmakingFindByID,
			buildMW2SessionIDRequest,
			"07c100980801000080888888888888880800",
		},
	}
	for _, golden := range goldens {
		want, err := hex.DecodeString(golden.encoded)
		if err != nil {
			t.Fatal(err)
		}
		got := golden.build(golden.operationID)
		if !bytes.Equal(got, want) {
			t.Fatalf("operation %d request=%x want=%x", golden.operationID, got, want)
		}
	}
}

func TestHandleRecoveredMW2FindSessionsReturnsEmptySuccess(t *testing.T) {
	connection := &lsgConnection{}
	responseType, payload, handled := connection.handleMatchmakingTask(buildMW2FindSessionsRequest())
	if !handled || responseType != lsgTaskReplyType || !connection.lastTaskSupported {
		t.Fatalf("type=%d handled=%v supported=%v payload=%x", responseType, handled, connection.lastTaskSupported, payload)
	}
	reader := mustBDTaskReplyReader(t, payload)
	if transaction, err := reader.readU64(); err != nil || transaction != 0 {
		t.Fatalf("transaction=%d err=%v", transaction, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("error=%d err=%v", errorCode, err)
	}
	if operationID, err := reader.readU8(); err != nil || operationID != bdMatchmakingFindSessions {
		t.Fatalf("operation=%d err=%v", operationID, err)
	}
	if count, err := reader.readU32(); err != nil || count != 0 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestMW2FindSessionsReplyMatchesRecoveredGoldenBits(t *testing.T) {
	// The result consumer at 0x003e1840 expects transaction, error, echoed
	// operation 5, and one result count. 0x004ef168 accepts count zero.
	want, err := hex.DecodeString("1500000000000000000200000018050800000000")
	if err != nil {
		t.Fatal(err)
	}
	got := (&lsgConnection{}).matchmakingFindReply(nil)
	if !bytes.Equal(got, want) {
		t.Fatalf("find-sessions reply=%x want=%x", got, want)
	}
}

func TestMW2NonemptyFindSessionsReplyMatchesRecoveredGoldenBits(t *testing.T) {
	// Independent golden from the result consumer at 0x00325c38:
	// base info followed by all nine title-specific I32 values.
	want, err := hex.DecodeString("1500000000000000000200000018052800000060a20c00000080008101820283038404850586068707880889098a0a8b0b8c8910000000020406080a0c0e10268200000080889098a0a8b0b8c0c8d0d8e0e8f0f8381200000027000000e0000000001c00000080130000007004000000ce000000c0210000003805000000c7000000e01c0000001c040000809300000000")
	if err != nil {
		t.Fatal(err)
	}
	session := mw2StoredMatchmakingSession{
		sessionID:     [mw2MatchmakingSessionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8},
		securityKey:   [mw2MatchmakingSecurityKeySize]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		openPublic:    18,
		filledPublic:  1,
		openPrivate:   0,
		filledPrivate: 0,
		attributes:    [9]int32{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	for index := range session.commonAddress {
		session.commonAddress[index] = byte(index)
	}
	got := (&lsgConnection{}).matchmakingFindReply([]mw2StoredMatchmakingSession{session})
	if !bytes.Equal(got, want) {
		t.Fatalf("nonempty find reply=%x want=%x", got, want)
	}
}

func TestMW2MutationRepliesMatchRecoveredGoldenBits(t *testing.T) {
	goldens := map[byte]string{
		bdMatchmakingUpdateSession: "150000000000000000020000001802",
		bdMatchmakingDeleteSession: "150000000000000000020000001803",
	}
	for operationID, encoded := range goldens {
		want, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		got := (&lsgConnection{}).matchmakingMutationReply(operationID)
		if !bytes.Equal(got, want) {
			t.Fatalf("operation %d reply=%x want=%x", operationID, got, want)
		}
	}
}

func TestMW2CreateReplyHasOneGeneratedIdentity(t *testing.T) {
	session := mw2StoredMatchmakingSession{
		sessionID:   [mw2MatchmakingSessionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8},
		securityKey: [mw2MatchmakingSecurityKeySize]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}
	reply := (&lsgConnection{}).matchmakingCreateReply(session)
	// Independent bit-level golden for transaction 0, success, op 1, count 1,
	// Blob[8] session ID, and Blob[16] security key.
	want, err := hex.DecodeString("1500000000000000000200000018012800000060220400008000810182028303848920000000201e1c1a18161412100e0c0a0806040200")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, want) {
		t.Fatalf("create reply=%x want=%x", reply, want)
	}
	reader := mustBDTaskReplyReader(t, reply)
	if transactionID, err := reader.readU64(); err != nil || transactionID != 0 {
		t.Fatalf("transaction=%d err=%v", transactionID, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("error=%d err=%v", errorCode, err)
	}
	if operationID, err := reader.readU8(); err != nil || operationID != bdMatchmakingCreateSession {
		t.Fatalf("operation=%d err=%v", operationID, err)
	}
	if count, err := reader.readU32(); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if sessionID, err := reader.readBlob(mw2MatchmakingSessionIDSize); err != nil || !bytes.Equal(sessionID, session.sessionID[:]) {
		t.Fatalf("session ID=%x err=%v", sessionID, err)
	}
	if securityKey, err := reader.readBlob(mw2MatchmakingSecurityKeySize); err != nil || !bytes.Equal(securityKey, session.securityKey[:]) {
		t.Fatalf("security key=%x err=%v", securityKey, err)
	}
}

func TestMW2SharedMatchmakingLifecycle(t *testing.T) {
	store := newMW2MatchmakingStore()
	creator := &lsgConnection{connectionID: 1, matchmakingSessions: store}
	_, createReply, handled := creator.handleMatchmakingTask(buildMW2SessionObjectRequest(bdMatchmakingCreateSession))
	if !handled || !creator.lastTaskSupported {
		t.Fatalf("create handled=%v supported=%v reply=%x", handled, creator.lastTaskSupported, createReply)
	}
	createResult := mustBDTaskReplyReader(t, createReply)
	if _, err := createResult.readU64(); err != nil {
		t.Fatal(err)
	}
	if errorCode, err := createResult.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("create error=%d err=%v", errorCode, err)
	}
	if operationID, err := createResult.readU8(); err != nil || operationID != bdMatchmakingCreateSession {
		t.Fatalf("create operation=%d err=%v", operationID, err)
	}
	if count, err := createResult.readU32(); err != nil || count != 1 {
		t.Fatalf("create count=%d err=%v", count, err)
	}
	sessionID, err := createResult.readBlob(mw2MatchmakingSessionIDSize)
	if err != nil {
		t.Fatal(err)
	}
	securityKey, err := createResult.readBlob(mw2MatchmakingSecurityKeySize)
	if err != nil {
		t.Fatal(err)
	}
	if allZero(sessionID) || allZero(securityKey) ||
		bytes.Equal(sessionID, bytes.Repeat([]byte{0x22}, mw2MatchmakingSessionIDSize)) ||
		bytes.Equal(securityKey, bytes.Repeat([]byte{0x33}, mw2MatchmakingSecurityKeySize)) {
		t.Fatalf("identity was not replaced: id=%x key=%x", sessionID, securityKey)
	}

	updatedAddress := bytes.Repeat([]byte{0x55}, mw2MatchmakingCommonAddressSize)
	updatedCounts := [4]int32{17, 2, 8, 4}
	updatedAttributes := [9]int32{90, 80, 70, 60, 50, 40, 30, 20, 10}
	updater := &lsgConnection{connectionID: 1, matchmakingSessions: store}
	updateRequest := buildMW2SessionObjectRequestWithValues(
		bdMatchmakingUpdateSession,
		updatedAddress,
		sessionID,
		bytes.Repeat([]byte{0x99}, mw2MatchmakingSecurityKeySize),
		updatedCounts,
		updatedAttributes,
	)
	_, updateReply, handled := updater.handleMatchmakingTask(updateRequest)
	if !handled || !updater.lastTaskSupported {
		t.Fatalf("update handled=%v supported=%v reply=%x", handled, updater.lastTaskSupported, updateReply)
	}
	updateGolden, _ := hex.DecodeString("150000000000000000020000001802")
	if !bytes.Equal(updateReply, updateGolden) {
		t.Fatalf("update reply=%x want=%x", updateReply, updateGolden)
	}

	searcher := &lsgConnection{connectionID: 2, matchmakingSessions: store}
	_, findReply, handled := searcher.handleMatchmakingTask(buildMW2FindSessionsRequestWithSearch(
		2,
		50,
		mw2MatchmakingSearch{
			gameType:          1,
			gameMode:          2,
			netcodeVersion:    3,
			mapPackFlags:      4,
			playlistVersion:   5,
			requiredFreeSlots: 6,
			performance:       7,
		},
	))
	if !handled || !searcher.lastTaskSupported {
		t.Fatalf("find handled=%v supported=%v reply=%x", handled, searcher.lastTaskSupported, findReply)
	}
	findResult := mustBDTaskReplyReader(t, findReply)
	if _, err := findResult.readU64(); err != nil {
		t.Fatal(err)
	}
	if errorCode, err := findResult.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("find error=%d err=%v", errorCode, err)
	}
	if operationID, err := findResult.readU8(); err != nil || operationID != bdMatchmakingFindSessions {
		t.Fatalf("find operation=%d err=%v", operationID, err)
	}
	if count, err := findResult.readU32(); err != nil || count != 1 {
		t.Fatalf("find count=%d err=%v", count, err)
	}
	found, err := readMW2MatchmakingInfo(findResult)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(found.commonAddress, updatedAddress) ||
		!bytes.Equal(found.sessionID, sessionID) ||
		!bytes.Equal(found.securityKey, securityKey) ||
		found.openPublic != updatedCounts[0] ||
		found.filledPublic != updatedCounts[1] ||
		found.openPrivate != updatedCounts[2] ||
		found.filledPrivate != updatedCounts[3] ||
		found.attributes != updatedAttributes {
		t.Fatalf("find result did not preserve updated state and identity: %+v", found)
	}

	deleter := &lsgConnection{connectionID: 1, matchmakingSessions: store}
	_, deleteReply, handled := deleter.handleMatchmakingTask(
		buildMW2SessionIDRequestWithValue(bdMatchmakingDeleteSession, sessionID),
	)
	if !handled || !deleter.lastTaskSupported {
		t.Fatalf("delete handled=%v supported=%v reply=%x", handled, deleter.lastTaskSupported, deleteReply)
	}
	deleteGolden, _ := hex.DecodeString("150000000000000000020000001803")
	if !bytes.Equal(deleteReply, deleteGolden) {
		t.Fatalf("delete reply=%x want=%x", deleteReply, deleteGolden)
	}
	if sessions := store.find(50, 0, false); len(sessions) != 0 {
		t.Fatalf("session survived deletion: %+v", sessions)
	}
}

func TestMW2FindSessionsExcludesRequestersOwnedSession(t *testing.T) {
	store := newMW2MatchmakingStore()
	requester := &lsgConnection{connectionID: 1, matchmakingSessions: store}
	peer := &lsgConnection{connectionID: 2, matchmakingSessions: store}

	_, requesterCreateReply, handled := requester.handleMatchmakingTask(buildMW2SessionObjectRequest(bdMatchmakingCreateSession))
	if !handled || !requester.lastTaskSupported {
		t.Fatalf("requester create handled=%v supported=%v reply=%x", handled, requester.lastTaskSupported, requesterCreateReply)
	}
	_, peerCreateReply, handled := peer.handleMatchmakingTask(buildMW2SessionObjectRequest(bdMatchmakingCreateSession))
	if !handled || !peer.lastTaskSupported {
		t.Fatalf("peer create handled=%v supported=%v reply=%x", handled, peer.lastTaskSupported, peerCreateReply)
	}

	readCreatedSessionID := func(reply []byte) []byte {
		t.Helper()
		reader := mustBDTaskReplyReader(t, reply)
		if _, err := reader.readU64(); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.readU32(); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.readU8(); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.readU32(); err != nil {
			t.Fatal(err)
		}
		sessionID, err := reader.readBlob(mw2MatchmakingSessionIDSize)
		if err != nil {
			t.Fatal(err)
		}
		return sessionID
	}
	requesterSessionID := readCreatedSessionID(requesterCreateReply)
	peerSessionID := readCreatedSessionID(peerCreateReply)

	findSessionID := func(connection *lsgConnection) []byte {
		t.Helper()
		_, reply, handled := connection.handleMatchmakingTask(buildMW2FindSessionsRequestWithSearch(
			2,
			50,
			mw2MatchmakingSearch{},
		))
		if !handled || !connection.lastTaskSupported {
			t.Fatalf("find handled=%v supported=%v reply=%x", handled, connection.lastTaskSupported, reply)
		}
		reader := mustBDTaskReplyReader(t, reply)
		if _, err := reader.readU64(); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.readU32(); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.readU8(); err != nil {
			t.Fatal(err)
		}
		if count, err := reader.readU32(); err != nil || count != 1 {
			t.Fatalf("count=%d err=%v reply=%x", count, err, reply)
		}
		if _, err := reader.readBlob(mw2MatchmakingCommonAddressSize); err != nil {
			t.Fatal(err)
		}
		sessionID, err := reader.readBlob(mw2MatchmakingSessionIDSize)
		if err != nil {
			t.Fatal(err)
		}
		return sessionID
	}

	if found := findSessionID(requester); !bytes.Equal(found, peerSessionID) {
		t.Fatalf("requester found=%x want peer=%x own=%x", found, peerSessionID, requesterSessionID)
	}
	if found := findSessionID(peer); !bytes.Equal(found, requesterSessionID) {
		t.Fatalf("peer found=%x want requester=%x own=%x", found, requesterSessionID, peerSessionID)
	}

	store.deleteOwner(peer.connectionID)
	_, reply, handled := requester.handleMatchmakingTask(buildMW2FindSessionsRequestWithSearch(
		2,
		50,
		mw2MatchmakingSearch{},
	))
	if !handled || !requester.lastTaskSupported {
		t.Fatalf("solo find handled=%v supported=%v reply=%x", handled, requester.lastTaskSupported, reply)
	}
	reader := mustBDTaskReplyReader(t, reply)
	if _, err := reader.readU64(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.readU32(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.readU8(); err != nil {
		t.Fatal(err)
	}
	if count, err := reader.readU32(); err != nil || count != 0 {
		t.Fatalf("solo count=%d err=%v reply=%x", count, err, reply)
	}
}

func TestMW2FindSessionsSelectsSlotPoolAndRequiredFreeSlots(t *testing.T) {
	store := newMW2MatchmakingStore()
	store.sessions[[mw2MatchmakingSessionIDSize]byte{1}] = mw2StoredMatchmakingSession{
		sessionID:   [mw2MatchmakingSessionIDSize]byte{1},
		openPublic:  2,
		openPrivate: 4,
		attributes:  [9]int32{11, 12, 13, 14, 15, 16, 17, 18, 19},
		ownerID:     1,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{2}] = mw2StoredMatchmakingSession{
		sessionID:   [mw2MatchmakingSessionIDSize]byte{2},
		openPublic:  3,
		openPrivate: 1,
		attributes:  [9]int32{91, 92, 93, 94, 95, 96, 97, 98, 99},
		ownerID:     2,
	}
	connection := &lsgConnection{connectionID: 3, matchmakingSessions: store}

	resultCount := func(search mw2MatchmakingSearch) uint32 {
		t.Helper()
		_, reply, handled := connection.handleMatchmakingTask(
			buildMW2FindSessionsRequestWithSearch(2, 50, search),
		)
		if !handled || !connection.lastTaskSupported {
			t.Fatalf("search was not handled: %+v reply=%x", search, reply)
		}
		reader := mustBDTaskReplyReader(t, reply)
		if _, err := reader.readU64(); err != nil {
			t.Fatal(err)
		}
		if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
			t.Fatalf("error=%d err=%v", errorCode, err)
		}
		if operationID, err := reader.readU8(); err != nil || operationID != bdMatchmakingFindSessions {
			t.Fatalf("operation=%d err=%v", operationID, err)
		}
		count, err := reader.readU32()
		if err != nil {
			t.Fatal(err)
		}
		return count
	}

	eligible := mw2MatchmakingSearch{
		gameType:          101,
		gameMode:          102,
		netcodeVersion:    103,
		mapPackFlags:      104,
		playlistVersion:   105,
		requiredFreeSlots: 3,
		performance:       106,
	}
	if count := resultCount(eligible); count != 1 {
		t.Fatalf("count=%d, want one unranked session with at least three private slots", count)
	}

	eligible.gameMode = -202
	eligible.netcodeVersion = -203
	eligible.mapPackFlags = -204
	eligible.playlistVersion = -205
	eligible.performance = -206
	if count := resultCount(eligible); count != 1 {
		t.Fatalf("unproven fields filtered sessions: count=%d", count)
	}

	eligible.requiredFreeSlots = 5
	if count := resultCount(eligible); count != 0 {
		t.Fatalf("insufficient private slots were returned: count=%d", count)
	}

	eligible.gameType = 0
	eligible.requiredFreeSlots = 3
	if count := resultCount(eligible); count != 1 {
		t.Fatalf("count=%d, want one ranked session with at least three public slots", count)
	}

	eligible.requiredFreeSlots = 4
	if count := resultCount(eligible); count != 0 {
		t.Fatalf("insufficient public slots were returned: count=%d", count)
	}
}

func TestMW2MissingMutationKeepsUnsupportedError(t *testing.T) {
	connection := &lsgConnection{matchmakingSessions: newMW2MatchmakingStore()}
	for _, payload := range [][]byte{
		buildMW2SessionObjectRequest(bdMatchmakingUpdateSession),
		buildMW2SessionIDRequest(bdMatchmakingDeleteSession),
	} {
		_, reply, handled := connection.handleMatchmakingTask(payload)
		if !handled || connection.lastTaskSupported {
			t.Fatalf("handled=%v supported=%v reply=%x", handled, connection.lastTaskSupported, reply)
		}
		result := mustBDTaskReplyReader(t, reply)
		if _, err := result.readU64(); err != nil {
			t.Fatal(err)
		}
		if errorCode, err := result.readU32(); err != nil || errorCode != bdErrorServiceNotAvailable {
			t.Fatalf("error=%d err=%v reply=%x", errorCode, err, reply)
		}
	}
}

func TestMW2FindSessionsRejectsNonRetailQuery(t *testing.T) {
	for _, test := range []struct {
		name       string
		queryType  int32
		maxResults int32
	}{
		{name: "query_type", queryType: 1, maxResults: 50},
		{name: "maximum", queryType: 2, maxResults: 49},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := buildMW2FindSessionsRequestWithSearch(
				test.queryType,
				test.maxResults,
				mw2MatchmakingSearch{
					gameType:          1,
					gameMode:          2,
					netcodeVersion:    3,
					mapPackFlags:      4,
					playlistVersion:   5,
					requiredFreeSlots: 6,
					performance:       7,
				},
			)
			connection := &lsgConnection{}
			_, reply, handled := connection.handleMatchmakingTask(payload)
			if !handled || connection.lastTaskSupported {
				t.Fatalf("handled=%v supported=%v reply=%x", handled, connection.lastTaskSupported, reply)
			}
			result := mustBDTaskReplyReader(t, reply)
			if _, err := result.readU64(); err != nil {
				t.Fatal(err)
			}
			if errorCode, err := result.readU32(); err != nil || errorCode != bdErrorServiceNotAvailable {
				t.Fatalf("error=%d err=%v reply=%x", errorCode, err, reply)
			}
		})
	}
}

func TestParseMW2MatchmakingRejectsBadSuffix(t *testing.T) {
	payload := buildMW2FindSessionsRequest()
	// The final five significant task bits are the zero terminator. Flip one.
	payload[len(payload)-1] |= 0x02
	if _, err := parseMW2MatchmakingRequest(payload); err == nil {
		t.Fatalf("accepted malformed suffix: %x", payload)
	}
}
