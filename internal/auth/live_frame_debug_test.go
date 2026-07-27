package auth

import (
	"encoding/hex"
	"testing"
)

func TestCapturedRPCNConnectionIDUsesTicketKey(t *testing.T) {
	frame, err := hex.DecodeString("1d000000010000000080453a1275ace758169f6f37012af5d080453a1275ace758")
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString("000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptLSGRecord(frame, key)
	if err != nil {
		t.Fatal(err)
	}
	if !decrypted.HMACValid {
		t.Fatalf("invalid captured HMAC: got=%08x expected=%08x plaintext=%x", decrypted.HMAC, decrypted.ExpectedHMAC, decrypted.Plaintext)
	}
	if decrypted.MessageType != lsgConnectionIDType {
		t.Fatalf("message type=%02x", decrypted.MessageType)
	}
}
