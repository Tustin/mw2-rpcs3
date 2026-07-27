package auth

import (
	"bytes"
	"testing"
)

func TestParseCapturedLSGHelloResponse(t *testing.T) {
	record, err := ParseLSGRecord(mustDecodeHex(capturedLSGHelloResponseHex))
	if err != nil {
		t.Fatal(err)
	}
	if record.Encrypted {
		t.Fatal("hello response unexpectedly encrypted")
	}
	if !bytes.Equal(record.Payload, mustDecodeHex("0415989b836e3dfbe515")) {
		t.Fatalf("payload=%x", record.Payload)
	}
}

func TestParseCapturedLSGKeyResponse(t *testing.T) {
	record, err := ParseLSGRecord(mustDecodeHex(capturedLSGKeyResponseHex))
	if err != nil {
		t.Fatal(err)
	}
	if !record.Encrypted {
		t.Fatal("key response unexpectedly plaintext")
	}
	if record.IVSeed != 0x86890ff9 {
		t.Fatalf("IV seed=%08x", record.IVSeed)
	}
	wantIV := mustDecodeHex("b173789462df7e11")
	if !bytes.Equal(record.IV[:], wantIV) {
		t.Fatalf("IV=%x", record.IV)
	}
	if len(record.Payload) != 56 {
		t.Fatalf("payload length=%d", len(record.Payload))
	}
}

func TestDecryptLSGRecord(t *testing.T) {
	message := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x00}
	const seed = 0x86890ff9
	frame, err := EncryptLSGRecord(message[0], message[1:], seed, candidateSessionKey[:])
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptLSGRecord(frame, candidateSessionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if !decrypted.HMACValid {
		t.Fatalf("HMAC=%08x expected=%08x", decrypted.HMAC, decrypted.ExpectedHMAC)
	}
	if decrypted.MessageType != message[0] {
		t.Fatalf("message type=%02x", decrypted.MessageType)
	}
	if !bytes.Equal(decrypted.Message[:len(message)], message) {
		t.Fatalf("message=%x", decrypted.Message)
	}
}

func TestCapturedLSGKeyResponseDoesNotMatchCapturedAuthKey(t *testing.T) {
	parsed, err := ParseLegacySuccessResponse(capturedMW2SuccessResponse)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptLSGRecord(mustDecodeHex(capturedLSGKeyResponseHex), parsed.SessionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if decrypted.HMACValid {
		t.Fatal("separately captured auth key unexpectedly validates LSG record")
	}
}

func TestDynamicClientLSGRequestUsesResponseSessionKey(t *testing.T) {
	frame := mustDecodeHex("250000000100000000018a645885c0959fea64f39ed298e33fecd1c5b9e4b9452c03fd77fe28d0bd7f")
	sessionKey := mustDecodeHex("5f30300000000000000100040000000000080018636f3853")
	decrypted, err := DecryptLSGRecord(frame, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if !decrypted.HMACValid {
		t.Fatalf("HMAC=%08x expected=%08x", decrypted.HMAC, decrypted.ExpectedHMAC)
	}
	wantPlaintext := mustDecodeHex("b972c25e0407c10038010000002800000040e96b8f7bf94413e0020000000000")
	if !bytes.Equal(decrypted.Plaintext, wantPlaintext) {
		t.Fatalf("plaintext=%x", decrypted.Plaintext)
	}
}
