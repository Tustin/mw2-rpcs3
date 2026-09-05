package auth

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

type realAuthCredentials struct {
	lsgKey     [24]byte
	sessionKey [24]byte
	gameTicket [legacyTicketLen]byte
	lsgTicket  [legacyTicketLen]byte
}

func buildRealAuthRetailRequest(gameID uint32, platformKey, lsgKey [24]byte) []byte {
	ticket := make([]byte, 284)
	copy(ticket[32:56], platformKey[:])
	copy(ticket[ps3LSGSessionKeyOffset:ps3LSGSessionKeyOffset+len(lsgKey)], lsgKey[:])

	payload := newLSBBitWriter(1 + 3*(5+32) + len(ticket)*8)
	payload.writeBit(true)
	for _, value := range []uint32{0x20254e8d, gameID, uint32(len(ticket))} {
		writeTypedUint32(payload, value)
	}
	payload.writeBytes(ticket)

	request := make([]byte, RetailRequestSize)
	binary.LittleEndian.PutUint32(request[:4], maxRetailRequestBodySize)
	request[4] = 0
	request[5] = 0x12
	copy(request[6:], payload.bytes())
	return request
}

func dialRealAuthServer(t *testing.T, address string) net.Conn {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", address, 250*time.Millisecond)
		if err == nil {
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				_ = conn.Close()
				t.Fatal(err)
			}
			return conn
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial raw server at %s: %v", address, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readRealAuthResponse(t *testing.T, conn net.Conn) []byte {
	t.Helper()

	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		t.Fatalf("read auth response length: %v", err)
	}
	bodyLength := binary.LittleEndian.Uint32(prefix[:])
	if bodyLength > RetailRequestSize {
		t.Fatalf("auth response body length=%d", bodyLength)
	}
	response := make([]byte, 4+bodyLength)
	copy(response, prefix[:])
	if _, err := io.ReadFull(conn, response[4:]); err != nil {
		t.Fatalf("read auth response body: %v", err)
	}
	return response
}

func authenticateRealAuthClient(
	t *testing.T,
	address string,
	platformKey, lsgKey [24]byte,
) realAuthCredentials {
	t.Helper()

	request := buildRealAuthRetailRequest(mw2GameID, platformKey, lsgKey)
	parsedRequest, err := ParseRetailAuthRequest(request)
	if err != nil {
		t.Fatalf("parse generated retail request: %v", err)
	}
	extractedLSGKey, err := parsePS3LSGSessionKey(parsedRequest.Ticket)
	if err != nil {
		t.Fatalf("extract generated request LSG key: %v", err)
	}
	if extractedLSGKey != lsgKey {
		t.Fatalf("request LSG key=%x want=%x", extractedLSGKey, lsgKey)
	}

	conn := dialRealAuthServer(t, address)
	if _, err := conn.Write(request); err != nil {
		_ = conn.Close()
		t.Fatalf("write auth request: %v", err)
	}
	response := readRealAuthResponse(t, conn)
	if err := conn.Close(); err != nil {
		t.Fatalf("close auth connection: %v", err)
	}

	parsed, err := ParseLegacySuccessResponse(response)
	if err != nil {
		t.Fatalf("parse auth response: %v", err)
	}
	if parsed.Status != bdAuthNoError {
		t.Fatalf("auth status=%d", parsed.Status)
	}
	if parsed.SessionKey == ([24]byte{}) {
		t.Fatal("auth returned zero session key")
	}

	gameTicket, err := parsed.DecryptGameTicket(platformKey[:])
	if err != nil {
		t.Fatalf("decrypt game ticket: %v", err)
	}
	gameSessionKey, err := ParseLegacyGameTicket(gameTicket[:])
	if err != nil {
		t.Fatalf("parse game ticket: %v", err)
	}
	if gameSessionKey != parsed.SessionKey {
		t.Fatalf("game-ticket key=%x response key=%x", gameSessionKey, parsed.SessionKey)
	}
	if want := buildLegacyGameTicket(parsed.SessionKey[:], mw2GameID); gameTicket != want {
		t.Fatalf("game ticket differs from exact production schema: got=%x want=%x", gameTicket, want)
	}

	lsgTicket := parsed.PlatformProof
	if want := buildCandidateLSGTicket(parsed.SessionKey[:]); lsgTicket != want {
		t.Fatalf("LSG ticket differs from exact production schema: got=%x want=%x", lsgTicket, want)
	}

	return realAuthCredentials{
		lsgKey:     lsgKey,
		sessionKey: parsed.SessionKey,
		gameTicket: gameTicket,
		lsgTicket:  lsgTicket,
	}
}

func connectRealAuthLSGClient(
	t *testing.T,
	address string,
	credentials realAuthCredentials,
	requestIV uint32,
) *fullFlowLSGClient {
	t.Helper()

	conn := dialRealAuthServer(t, address)
	if _, err := conn.Write(buildLSGInitialRecord(mw2GameID, requestIV, credentials.lsgTicket)); err != nil {
		_ = conn.Close()
		t.Fatalf("write LSG initial record: %v", err)
	}
	hello, err := readLSGFrame(conn, RetailRequestSize)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read LSG hello: %v", err)
	}
	record, err := ParseLSGRecord(hello)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("parse LSG hello: %v", err)
	}
	if record.Encrypted || len(record.Payload) != 9 || record.Payload[0]&0x1f != lsgConnectionType {
		_ = conn.Close()
		t.Fatalf("unexpected LSG hello: %x", hello)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil && !isClosedNetworkError(err) {
			t.Errorf("close LSG connection: %v", err)
		}
	})
	return &fullFlowLSGClient{conn: conn, key: credentials.lsgKey, nextIV: requestIV}
}

func isClosedNetworkError(err error) bool {
	return err != nil && bytes.Contains([]byte(err.Error()), []byte("use of closed network connection"))
}

func assertRealAuthTicketReplayRejected(
	t *testing.T,
	address string,
	ticket [legacyTicketLen]byte,
	requestIV uint32,
) {
	t.Helper()

	conn := dialRealAuthServer(t, address)
	defer conn.Close()
	if _, err := conn.Write(buildLSGInitialRecord(mw2GameID, requestIV, ticket)); err != nil {
		t.Fatalf("write replayed LSG ticket: %v", err)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err == nil {
		t.Fatalf("replayed LSG ticket received response prefix=%x", prefix)
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("replayed LSG ticket was not promptly rejected: %v", err)
	}
}

func startRealAuthRawServer(t *testing.T, playlistPath string) (*RawServer, string) {
	t.Helper()

	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	t.Setenv("MW2_PLAYLISTS_FILE", playlistPath)
	service := NewRawServer(
		address,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		capture.New(false, "", 16<<20),
		5*time.Second,
		5*time.Second,
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- service.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("raw server stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("raw server did not stop")
		}
	})
	return service, address
}

func TestRawServerRetailAuthTwoClientStorageAndMatchmakingFlow(t *testing.T) {
	playlistPath, err := filepath.Abs("../../playlists.info")
	if err != nil {
		t.Fatal(err)
	}
	playlist, err := os.ReadFile(playlistPath)
	if err != nil {
		t.Fatal(err)
	}
	service, address := startRealAuthRawServer(t, playlistPath)

	hostPlatformKey := candidateSessionKey
	hostLSGKey := candidateSessionKey
	seekerPlatformKey := candidateSessionKey
	seekerPlatformKey[0] ^= 0x36
	seekerLSGKey := candidateSessionKey
	seekerLSGKey[0] ^= 0x5a

	hostCredentials := authenticateRealAuthClient(t, address, hostPlatformKey, hostLSGKey)
	seekerCredentials := authenticateRealAuthClient(t, address, seekerPlatformKey, seekerLSGKey)
	if hostCredentials.sessionKey == seekerCredentials.sessionKey {
		t.Fatalf("clients received same session key: %x", hostCredentials.sessionKey)
	}
	if hostCredentials.gameTicket == seekerCredentials.gameTicket {
		t.Fatal("clients received same game ticket")
	}
	if hostCredentials.lsgTicket == seekerCredentials.lsgTicket {
		t.Fatal("clients received same LSG ticket")
	}
	if hostCredentials.lsgKey == seekerCredentials.lsgKey {
		t.Fatalf("clients use same LSG key: %x", hostCredentials.lsgKey)
	}

	host := connectRealAuthLSGClient(t, address, hostCredentials, 0x10000000)
	seeker := connectRealAuthLSGClient(t, address, seekerCredentials, 0x20000000)
	assertRealAuthTicketReplayRejected(t, address, hostCredentials.lsgTicket, 0x30000000)
	assertRealAuthTicketReplayRejected(t, address, seekerCredentials.lsgTicket, 0x40000000)

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
	hostAttributes := [9]int32{101, 1, 105, 3, 103, 104, 102, 7, 504}
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
	updateReply := host.exchange(t, bdServiceMatchmaking, buildMW2SessionObjectRequestWithValues(
		bdMatchmakingUpdateSession,
		hostAddress,
		sessionID,
		securityKey,
		hostCounts,
		hostAttributes,
	))
	assertFullFlowMutationReply(t, updateReply, 4, bdMatchmakingUpdateSession)

	findReply := seeker.exchange(t, bdServiceMatchmaking, buildMW2FindSessionsRequestWithValues(
		2,
		50,
		[6]int32{101, 102, 103, 104, 105, 1},
		504,
	))
	found := readFullFlowFindReply(t, findReply, 3)
	if len(found) != 1 {
		t.Fatalf("find count=%d, want one exact host candidate", len(found))
	}
	resultCounts := [4]int32{8, 1, 8, 0}
	assertFullFlowCandidate(
		t,
		found[0],
		hostAddress,
		sessionID,
		securityKey,
		resultCounts,
		hostAttributes,
	)

	if got, want := service.Connections(), uint64(6); got != want {
		t.Fatalf("connections=%d want=%d", got, want)
	}
	if got, want := service.Requests(), uint64(2); got != want {
		t.Fatalf("auth requests=%d want=%d", got, want)
	}
	if got, want := service.LSGConnections(), uint64(4); got != want {
		t.Fatalf("LSG connections=%d want=%d", got, want)
	}
	if got, want := service.LSGFrames(), uint64(13); got != want {
		t.Fatalf("LSG frames=%d want=%d", got, want)
	}

	t.Logf(
		"production counters: connections=%d auth=%d LSG connections=%d frames=%d",
		service.Connections(),
		service.Requests(),
		service.LSGConnections(),
		service.LSGFrames(),
	)
}
