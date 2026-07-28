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
	if len(response) != 11 || response[8] != 1 || binary.LittleEndian.Uint16(response[9:]) != bdErrorServiceNotAvailable {
		t.Fatalf("malformed bandwidth reply=%x", response)
	}
}
