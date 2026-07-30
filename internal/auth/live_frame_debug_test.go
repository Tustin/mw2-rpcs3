package auth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestCapturedRPCNBandwidthRequestReachesRawTaskHandler(t *testing.T) {
	frame, err := hex.DecodeString("1d000000010000000080453a1275ace758169f6f37012af5d080453a1275ace758")
	if err != nil {
		t.Fatal(err)
	}
	var key [24]byte
	session, err := newLSGConnection(key)
	if err != nil {
		t.Fatal(err)
	}
	session.bandwidthIPv4 = [4]byte{192, 0, 2, 25}
	session.bandwidthPort = 3074
	session.bandwidthConfigured = true

	serviceID, payload, err := session.decryptRequest(frame)
	if err != nil {
		t.Fatal(err)
	}
	if serviceID != bdServiceBandwidth {
		t.Fatalf("service ID=%02x", serviceID)
	}
	wantPayload, err := hex.DecodeString("01000100000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, wantPayload) {
		t.Fatalf("payload=%x want=%x", payload, wantPayload)
	}

	responseType, response, handled, reply := handleLSGMessage(session, serviceID, payload)
	if !handled || !reply || responseType != lsgServiceTaskReplyType {
		t.Fatalf("response type=%d payload=%x handled=%v reply=%v", responseType, response, handled, reply)
	}
	if !session.lastTaskSupported || session.lastServiceID != bdServiceBandwidth || session.lastOperationID != 1 {
		t.Fatalf("supported=%v service=%d operation=%d", session.lastTaskSupported, session.lastServiceID, session.lastOperationID)
	}
	if len(response) != 51 || response[8] != 0 ||
		binary.LittleEndian.Uint32(response[9:13]) != 512 ||
		binary.LittleEndian.Uint32(response[13:17]) != 5 ||
		binary.LittleEndian.Uint16(response[37:39]) != 3074 ||
		!bytes.Equal(response[39:43], []byte{192, 0, 2, 25}) ||
		!bytes.Equal(response[43:51], []byte{0, 1, 2, 3, 4, 5, 6, 7}) {
		t.Fatalf("malformed bandwidth reply=%x", response)
	}
}
