package auth

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
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
	if parsed.PlatformKey != candidateSessionKey {
		t.Fatalf("platform key=%x", parsed.PlatformKey)
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
	for name, want := range map[string]uint32{"status": bdAuthNoError, "iv seed": ivSeed} {
		got, err := reader.readBits(32)
		if err != nil || uint32(got) != want {
			t.Fatalf("%s=%08x err=%v", name, got, err)
		}
	}
	if _, err := reader.readBytes(legacyTicketLen * 2); err != nil {
		t.Fatal(err)
	}
	gotSessionKey, err := reader.readBytes(len(candidateSessionKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSessionKey, candidateSessionKey[:]) {
		t.Fatalf("wire session key=%x", gotSessionKey)
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

func TestRawServerSendsLegacySuccess(t *testing.T) {
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
	wantPrefix := []byte{0x23, 0x01, 0x00, 0x00, 0x00, legacyReplyType}
	if !bytes.Equal(response[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("unexpected response prefix %x", response[:len(wantPrefix)])
	}
	_ = client.Close()
	<-done
	if service.Requests() != 1 {
		t.Fatalf("requests=%d", service.Requests())
	}
}
