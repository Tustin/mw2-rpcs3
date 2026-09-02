package auth

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

type fullFlowLSGClient struct {
	conn   net.Conn
	key    [24]byte
	nextIV uint32
}

func newFullFlowLSGClient(
	t *testing.T,
	service *RawServer,
	ticketID byte,
	key [24]byte,
	requestIV uint32,
) *fullFlowLSGClient {
	t.Helper()

	var ticket [legacyTicketLen]byte
	for index := 0; index < 24; index++ {
		ticket[index] = ticketID
	}
	service.sessionStore().put(ticket, key)

	clientConn, serverConn := net.Pipe()
	done := make(chan struct{})
	go func() {
		service.handle(serverConn)
		close(done)
	}()
	t.Cleanup(func() {
		_ = clientConn.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("LSG server connection did not stop")
		}
	})

	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(buildLSGInitialRecord(mw2GameID, requestIV, ticket)); err != nil {
		t.Fatal(err)
	}
	hello, err := readLSGFrame(clientConn, RetailRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	record, err := ParseLSGRecord(hello)
	if err != nil {
		t.Fatal(err)
	}
	if record.Encrypted || len(record.Payload) != 9 {
		t.Fatalf("unexpected LSG hello: %x", hello)
	}

	return &fullFlowLSGClient{conn: clientConn, key: key, nextIV: requestIV}
}

func (c *fullFlowLSGClient) exchange(t *testing.T, serviceID byte, payload []byte) []byte {
	t.Helper()

	frame, err := EncryptLSGRecord(serviceID, payload, c.nextIV, c.key[:])
	if err != nil {
		t.Fatal(err)
	}
	c.nextIV++
	if err := c.conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	response, err := readLSGFrame(c.conn, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	session := &lsgConnection{key: c.key}
	messageType, responsePayload, err := session.decryptResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != lsgTaskReplyType {
		t.Fatalf("response message type=%d payload=%x", messageType, responsePayload)
	}
	return responsePayload
}

func readFullFlowFileInfo(t *testing.T, reader *bdBitReader, expectedName string) uint64 {
	t.Helper()

	fileID, err := reader.readU64()
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		if value, readErr := reader.readU32(); readErr != nil || value != 0 {
			t.Fatalf("file info u32[%d]=%d err=%v", index, value, readErr)
		}
	}
	for index := 0; index < 2; index++ {
		if err := reader.readType(bdTypeBool); err != nil {
			t.Fatal(err)
		}
		if value, readErr := reader.bits.readBits(1); readErr != nil || value != 0 {
			t.Fatalf("file info bool[%d]=%d err=%v", index, value, readErr)
		}
	}
	if value, err := reader.readU64(); err != nil || value != 0 {
		t.Fatalf("file info u64=%d err=%v", value, err)
	}
	if filename, err := readBDTestString(reader); err != nil || filename != expectedName {
		t.Fatalf("file info name=%q err=%v", filename, err)
	}
	return fileID
}

func assertFullFlowStorage(t *testing.T, client *fullFlowLSGClient, playlist []byte) {
	t.Helper()

	listReply := client.exchange(
		t,
		bdServiceStorage,
		buildMW2StorageListRequestWith(0, 100, ""),
	)
	list := mustBDTaskReplyReader(t, listReply)
	if transaction, err := list.readU64(); err != nil || transaction != 0 {
		t.Fatalf("op8 transaction=%d err=%v", transaction, err)
	}
	if errorCode, err := list.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("op8 error=%d err=%v", errorCode, err)
	}
	if operationID, err := list.readU8(); err != nil || operationID != bdStorageListFiles {
		t.Fatalf("op8 operation=%d err=%v", operationID, err)
	}
	if count, err := list.readU32(); err != nil || count != 3 {
		t.Fatalf("op8 count=%d err=%v", count, err)
	}
	if size, err := list.readU32(); err != nil || size != uint32(len(mw2DefaultMOTD)) {
		t.Fatalf("op8 MOTD size=%d want=%d err=%v", size, len(mw2DefaultMOTD), err)
	}
	motdFileID := readFullFlowFileInfo(t, list, mw2MOTDFilename)
	if motdFileID != mw2MOTDFileID {
		t.Fatalf("op8 MOTD file ID=%x", motdFileID)
	}
	if size, err := list.readU32(); err != nil || size != uint32(len(playlist)) {
		t.Fatalf("op8 size=%d want=%d err=%v", size, len(playlist), err)
	}
	fileID := readFullFlowFileInfo(t, list, mw2PlaylistFilename)
	if fileID != mw2PlaylistFileID {
		t.Fatalf("op8 file ID=%x", fileID)
	}
	if size, err := list.readU32(); err != nil || size != uint32(len(playlist)) {
		t.Fatalf("op8 title-update size=%d want=%d err=%v", size, len(playlist), err)
	}
	patch3FileID := readFullFlowFileInfo(t, list, mw2PlaylistPatch3Name)
	if patch3FileID != mw2PlaylistPatch3FileID {
		t.Fatalf("op8 title-update file ID=%x", patch3FileID)
	}

	motdReply := client.exchange(t, bdServiceStorage, buildMW2StorageGetRequest(motdFileID))
	motd := mustBDTaskReplyReader(t, motdReply)
	if transaction, err := motd.readU64(); err != nil || transaction != 1 {
		t.Fatalf("MOTD op5 transaction=%d err=%v", transaction, err)
	}
	if errorCode, err := motd.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("MOTD op5 error=%d err=%v", errorCode, err)
	}
	if operationID, err := motd.readU8(); err != nil || operationID != bdStorageGetFile {
		t.Fatalf("MOTD op5 operation=%d err=%v", operationID, err)
	}
	if size, err := motd.readU32(); err != nil || size != uint32(len(mw2DefaultMOTD)) {
		t.Fatalf("MOTD op5 size=%d want=%d err=%v", size, len(mw2DefaultMOTD), err)
	}
	if returnedID := readFullFlowFileInfo(t, motd, mw2MOTDFilename); returnedID != motdFileID {
		t.Fatalf("MOTD op5 file ID=%x want=%x", returnedID, motdFileID)
	}
	motdBlob, err := motd.readBlob(mw2MOTDMaxSize)
	if err != nil {
		t.Fatal(err)
	}
	if string(motdBlob) != mw2DefaultMOTD {
		t.Fatalf("MOTD op5 blob=%q", motdBlob)
	}

	getReply := client.exchange(t, bdServiceStorage, buildMW2StorageGetRequest(fileID))
	get := mustBDTaskReplyReader(t, getReply)
	if transaction, err := get.readU64(); err != nil || transaction != 2 {
		t.Fatalf("op5 transaction=%d err=%v", transaction, err)
	}
	if errorCode, err := get.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("op5 error=%d err=%v", errorCode, err)
	}
	if operationID, err := get.readU8(); err != nil || operationID != bdStorageGetFile {
		t.Fatalf("op5 operation=%d err=%v", operationID, err)
	}
	if size, err := get.readU32(); err != nil || size != uint32(len(playlist)) {
		t.Fatalf("op5 size=%d want=%d err=%v", size, len(playlist), err)
	}
	if returnedID := readFullFlowFileInfo(t, get, mw2PlaylistFilename); returnedID != fileID {
		t.Fatalf("op5 file ID=%x want=%x", returnedID, fileID)
	}
	if err := get.readType(bdTypeBlob); err != nil {
		t.Fatal(err)
	}
	blobLength, err := get.readU32()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := get.bits.readBytes(int(blobLength))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, playlist) {
		t.Fatalf("op5 playlist differs: got=%d want=%d", len(blob), len(playlist))
	}
}

func TestAuthenticatedLSGSurvivesGeneralReadTimeoutThenExpiresIdle(t *testing.T) {
	const readTimeout = 40 * time.Millisecond
	service := NewRawServer(
		"unused",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		capture.New(false, "", 16<<20),
		readTimeout,
		5*time.Second,
	)
	service.lsgIdleTimeout = 6 * readTimeout
	client := newFullFlowLSGClient(t, service, 0x7a, candidateSessionKey, 0x71000000)

	createReply := client.exchange(
		t,
		bdServiceMatchmaking,
		buildMW2SessionObjectRequest(bdMatchmakingCreateSession),
	)
	readFullFlowCreateReply(t, createReply, 0)

	// Cross several general read-timeout intervals. Authenticated LSG uses its
	// longer dedicated idle limit and must not disconnect or reclaim a host
	// before the client's proven 180-second refresh cadence.
	time.Sleep(4 * readTimeout)
	findReply := client.exchange(
		t,
		bdServiceMatchmaking,
		buildMW2FindSessionsRequestWithSearch(2, 50, mw2MatchmakingSearch{
			gameType:        1,
			gameMode:        7,
			netcodeVersion:  5,
			mapPackFlags:    6,
			playlistVersion: 3,
		}),
	)
	if found := readFullFlowFindReply(t, findReply, 1); len(found) != 1 {
		t.Fatalf("self-inclusive session disappeared across read deadlines: %+v", found)
	}
	if sessions := service.matchmakingStore().find(1, 0, false); len(sessions) != 1 {
		t.Fatalf("session disappeared across read deadlines: %+v", sessions)
	}

	// With no further traffic, the finite authenticated-LSG idle limit must
	// close the connection and reclaim the record.
	deadline := time.Now().Add(2 * time.Second)
	for len(service.matchmakingStore().find(1, 0, false)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("owned matchmaking session survived LSG connection close")
		}
		time.Sleep(time.Millisecond)
	}
}

func readFullFlowCreateReply(t *testing.T, payload []byte, transaction uint64) ([]byte, []byte) {
	t.Helper()

	reader := mustBDTaskReplyReader(t, payload)
	if value, err := reader.readU64(); err != nil || value != transaction {
		t.Fatalf("create transaction=%d want=%d err=%v", value, transaction, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("create error=%d err=%v", errorCode, err)
	}
	if operationID, err := reader.readU8(); err != nil || operationID != bdMatchmakingCreateSession {
		t.Fatalf("create operation=%d err=%v", operationID, err)
	}
	if count, err := reader.readU32(); err != nil || count != 1 {
		t.Fatalf("create count=%d err=%v", count, err)
	}
	sessionID, err := reader.readBlob(mw2MatchmakingSessionIDSize)
	if err != nil {
		t.Fatal(err)
	}
	securityKey, err := reader.readBlob(mw2MatchmakingSecurityKeySize)
	if err != nil {
		t.Fatal(err)
	}
	return sessionID, securityKey
}

func readFullFlowFindReply(
	t *testing.T,
	payload []byte,
	transaction uint64,
) []mw2MatchmakingInfo {
	t.Helper()

	reader := mustBDTaskReplyReader(t, payload)
	if value, err := reader.readU64(); err != nil || value != transaction {
		t.Fatalf("find transaction=%d want=%d err=%v", value, transaction, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("find error=%d err=%v", errorCode, err)
	}
	if operationID, err := reader.readU8(); err != nil || operationID != bdMatchmakingFindSessions {
		t.Fatalf("find operation=%d err=%v", operationID, err)
	}
	count, err := reader.readU32()
	if err != nil {
		t.Fatal(err)
	}
	results := make([]mw2MatchmakingInfo, 0, count)
	for index := uint32(0); index < count; index++ {
		result, readErr := readMW2MatchmakingInfo(reader)
		if readErr != nil {
			t.Fatalf("find result %d: %v", index, readErr)
		}
		results = append(results, result)
	}
	return results
}

func assertFullFlowCandidate(
	t *testing.T,
	candidate mw2MatchmakingInfo,
	commonAddress, sessionID, securityKey []byte,
	counts [4]int32,
	attributes [9]int32,
) {
	t.Helper()

	if !bytes.Equal(candidate.commonAddress, commonAddress) ||
		!bytes.Equal(candidate.sessionID, sessionID) ||
		!bytes.Equal(candidate.securityKey, securityKey) ||
		candidate.openPublic != counts[0] ||
		candidate.filledPublic != counts[1] ||
		candidate.openPrivate != counts[2] ||
		candidate.filledPrivate != counts[3] ||
		candidate.attributes != attributes {
		t.Fatalf(
			"candidate mismatch: got=%+v address=%x session=%x key=%x counts=%v attributes=%v",
			candidate,
			commonAddress,
			sessionID,
			securityKey,
			counts,
			attributes,
		)
	}
}

func assertFullFlowMutationReply(
	t *testing.T,
	payload []byte,
	transaction uint64,
	operationID byte,
) {
	t.Helper()

	reader := mustBDTaskReplyReader(t, payload)
	if value, err := reader.readU64(); err != nil || value != transaction {
		t.Fatalf("mutation transaction=%d want=%d err=%v", value, transaction, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("mutation error=%d err=%v", errorCode, err)
	}
	if operation, err := reader.readU8(); err != nil || operation != operationID {
		t.Fatalf("mutation operation=%d want=%d err=%v", operation, operationID, err)
	}
}

func TestRawServerTwoClientStorageToMatchmakingCandidateFlow(t *testing.T) {
	playlistPath, err := filepath.Abs("../../playlists.info")
	if err != nil {
		t.Fatal(err)
	}
	playlist, err := os.ReadFile(playlistPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MW2_PLAYLISTS_FILE", playlistPath)

	service := NewRawServer(
		"",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		capture.New(false, "", 16<<20),
		5*time.Second,
		5*time.Second,
	)
	hostKey := candidateSessionKey
	seekerKey := candidateSessionKey
	seekerKey[0] ^= 0x5a
	host := newFullFlowLSGClient(t, service, 0xa1, hostKey, 0x10000000)
	seeker := newFullFlowLSGClient(t, service, 0xb2, seekerKey, 0x20000000)

	assertFullFlowStorage(t, host, playlist)
	assertFullFlowStorage(t, seeker, playlist)

	hostAddress := []byte{
		10, 1, 2, 3, 0x02, 0x0c,
		0x00, 0xff, 0x00, 0xff, 0x00, 0x00,
		0x00, 0xff, 0x00, 0xff, 0x00, 0x00,
		203, 0, 113, 7, 0x02, 0x0c,
		2,
	}
	hostCounts := [4]int32{0, 1, 8, 0}
	hostAttributes := [9]int32{101, 0, 105, 0, 103, 104, 102, 0, 504}
	createReply := host.exchange(t, bdServiceMatchmaking, buildMW2SessionObjectRequestWithValues(
		bdMatchmakingCreateSession,
		hostAddress,
		make([]byte, mw2MatchmakingSessionIDSize),
		make([]byte, mw2MatchmakingSecurityKeySize),
		hostCounts,
		hostAttributes,
	))
	sessionID, securityKey := readFullFlowCreateReply(t, createReply, 3)
	if allZero(sessionID) || allZero(securityKey) {
		t.Fatalf("create returned zero identity: session=%x key=%x", sessionID, securityKey)
	}
	seekerAddress := append([]byte(nil), hostAddress...)
	seekerAddress[3] = 4
	seekerCreateReply := seeker.exchange(t, bdServiceMatchmaking, buildMW2SessionObjectRequestWithValues(
		bdMatchmakingCreateSession,
		seekerAddress,
		make([]byte, mw2MatchmakingSessionIDSize),
		make([]byte, mw2MatchmakingSecurityKeySize),
		hostCounts,
		hostAttributes,
	))
	seekerSessionID, seekerSecurityKey := readFullFlowCreateReply(t, seekerCreateReply, 3)
	if allZero(seekerSessionID) || allZero(seekerSecurityKey) {
		t.Fatalf("seeker create returned zero identity: session=%x key=%x", seekerSessionID, seekerSecurityKey)
	}

	findRequest := buildMW2FindSessionsRequestWithValues(
		2,
		50,
		[6]int32{101, 102, 103, 104, 105, 1},
		504,
	)
	for _, session := range []struct {
		client      *fullFlowLSGClient
		address     []byte
		sessionID   []byte
		securityKey []byte
	}{
		{client: host, address: hostAddress, sessionID: sessionID, securityKey: securityKey},
		{client: seeker, address: seekerAddress, sessionID: seekerSessionID, securityKey: seekerSecurityKey},
	} {
		updateReply := session.client.exchange(t, bdServiceMatchmaking, buildMW2SessionObjectRequestWithValues(
			bdMatchmakingUpdateSession,
			session.address,
			session.sessionID,
			session.securityKey,
			hostCounts,
			hostAttributes,
		))
		assertFullFlowMutationReply(t, updateReply, 4, bdMatchmakingUpdateSession)
	}
	for _, client := range []*fullFlowLSGClient{host, seeker} {
		found := readFullFlowFindReply(
			t,
			client.exchange(t, bdServiceMatchmaking, findRequest),
			5,
		)
		if len(found) != 2 {
			t.Fatalf("initial find count=%d", len(found))
		}
		hostResultCounts := hostCounts
		seekerResultCounts := hostCounts
		if client == host {
			seekerResultCounts[0] = mw2RemoteFindOpenPublicSlotFloor
		} else {
			hostResultCounts[0] = mw2RemoteFindOpenPublicSlotFloor
		}
		assertFullFlowCandidate(
			t,
			found[0],
			hostAddress,
			sessionID,
			securityKey,
			hostResultCounts,
			hostAttributes,
		)
		assertFullFlowCandidate(
			t,
			found[1],
			seekerAddress,
			seekerSessionID,
			seekerSecurityKey,
			seekerResultCounts,
			hostAttributes,
		)
	}

	updatedAddress := append([]byte(nil), hostAddress...)
	updatedAddress[21] = 8
	updatedAddress[24] = 1
	updatedCounts := [4]int32{0, 2, 7, 1}
	updatedAttributes := [9]int32{101, 8, 105, 6, 103, 104, 102, 2, 505}
	updateReply := host.exchange(t, bdServiceMatchmaking, buildMW2SessionObjectRequestWithValues(
		bdMatchmakingUpdateSession,
		updatedAddress,
		sessionID,
		securityKey,
		updatedCounts,
		updatedAttributes,
	))
	assertFullFlowMutationReply(t, updateReply, 6, bdMatchmakingUpdateSession)

	found := readFullFlowFindReply(
		t,
		seeker.exchange(t, bdServiceMatchmaking, findRequest),
		6,
	)
	if len(found) != 2 {
		t.Fatalf("updated find count=%d", len(found))
	}
	updatedResultCounts := updatedCounts
	updatedResultCounts[0] = mw2RemoteFindOpenPublicSlotFloor
	assertFullFlowCandidate(
		t,
		found[0],
		updatedAddress,
		sessionID,
		securityKey,
		updatedResultCounts,
		updatedAttributes,
	)
	assertFullFlowCandidate(
		t,
		found[1],
		seekerAddress,
		seekerSessionID,
		seekerSecurityKey,
		hostCounts,
		hostAttributes,
	)

	deleteReply := host.exchange(
		t,
		bdServiceMatchmaking,
		buildMW2SessionIDRequestWithValue(bdMatchmakingDeleteSession, sessionID),
	)
	assertFullFlowMutationReply(t, deleteReply, 7, bdMatchmakingDeleteSession)
	found = readFullFlowFindReply(
		t,
		seeker.exchange(t, bdServiceMatchmaking, findRequest),
		7,
	)
	if len(found) != 1 {
		t.Fatalf("post-delete find count=%d", len(found))
	}
	assertFullFlowCandidate(
		t,
		found[0],
		seekerAddress,
		seekerSessionID,
		seekerSecurityKey,
		hostCounts,
		hostAttributes,
	)

	// A nonempty retail result hands this exact address/ID/key tuple to the
	// client's peer router. Peer QoS and traversal begin after this boundary
	// and are intentionally outside this central-service harness.
	if service.LSGConnections() != 2 || service.LSGFrames() != 18 {
		t.Fatalf(
			"LSG connections=%d frames=%d",
			service.LSGConnections(),
			service.LSGFrames(),
		)
	}
}
