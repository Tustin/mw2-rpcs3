package auth

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
)

const lsgEncryptedHeaderLen = 9

type LSGRecord struct {
	Encrypted bool
	IVSeed    uint32
	IV        [des.BlockSize]byte
	Payload   []byte
}

type DecryptedLSGRecord struct {
	LSGRecord
	Plaintext    []byte
	Message      []byte
	MessageType  byte
	HMAC         uint32
	ExpectedHMAC uint32
	HMACValid    bool
}

func ParseLSGRecord(frame []byte) (LSGRecord, error) {
	if len(frame) < 5 {
		return LSGRecord{}, fmt.Errorf("LSG frame too short: %d", len(frame))
	}
	bodyLength := binary.LittleEndian.Uint32(frame[:4])
	if int(bodyLength) != len(frame)-4 {
		return LSGRecord{}, fmt.Errorf("LSG body length is %d, got %d bytes", bodyLength, len(frame)-4)
	}

	record := LSGRecord{Encrypted: frame[4] != 0}
	if !record.Encrypted {
		record.Payload = append([]byte(nil), frame[5:]...)
		return record, nil
	}
	if len(frame) < lsgEncryptedHeaderLen {
		return LSGRecord{}, fmt.Errorf("encrypted LSG frame too short: %d", len(frame))
	}
	record.IVSeed = binary.LittleEndian.Uint32(frame[5:9])
	copy(record.IV[:], tigerDigest(frame[5:9])[:des.BlockSize])
	record.Payload = append([]byte(nil), frame[9:]...)
	if len(record.Payload) == 0 || len(record.Payload)%des.BlockSize != 0 {
		return LSGRecord{}, fmt.Errorf("encrypted LSG payload length must be a positive multiple of %d, got %d", des.BlockSize, len(record.Payload))
	}
	return record, nil
}

func EncryptLSGRecord(messageType byte, payload []byte, ivSeed uint32, sessionKey []byte) ([]byte, error) {
	if len(sessionKey) != 24 {
		return nil, fmt.Errorf("LSG session key length must be 24 bytes, got %d", len(sessionKey))
	}
	block, err := des.NewTripleDESCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("create LSG 3DES cipher: %w", err)
	}

	plainLength := 5 + len(payload)
	paddedLength := (plainLength + des.BlockSize - 1) / des.BlockSize * des.BlockSize
	plaintext := make([]byte, paddedLength)
	plaintext[4] = messageType
	copy(plaintext[5:], payload)
	binary.LittleEndian.PutUint32(plaintext[:4], lsgHMAC(plaintext[5:], sessionKey))

	seedBytes := littleEndianUint32(ivSeed)
	iv := tigerDigest(seedBytes)[:des.BlockSize]
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	frame := make([]byte, lsgEncryptedHeaderLen+len(ciphertext))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(frame)-4))
	frame[4] = 1
	copy(frame[5:9], seedBytes)
	copy(frame[9:], ciphertext)
	return frame, nil
}

func EncryptLSGServerRecord(messageType byte, payload []byte, ivSeed uint32, sessionKey []byte) ([]byte, error) {
	if len(sessionKey) != 24 {
		return nil, fmt.Errorf("LSG session key length must be 24 bytes, got %d", len(sessionKey))
	}
	block, err := des.NewTripleDESCipher(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("create LSG 3DES cipher: %w", err)
	}

	plainLength := 5 + len(payload)
	paddedLength := (plainLength + des.BlockSize - 1) / des.BlockSize * des.BlockSize
	plaintext := make([]byte, paddedLength)
	binary.LittleEndian.PutUint32(plaintext[:4], 0xdeadbeef)
	plaintext[4] = messageType
	copy(plaintext[5:], payload)

	seedBytes := littleEndianUint32(ivSeed)
	iv := tigerDigest(seedBytes)[:des.BlockSize]
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)

	frame := make([]byte, lsgEncryptedHeaderLen+len(ciphertext))
	binary.LittleEndian.PutUint32(frame[:4], uint32(len(frame)-4))
	frame[4] = 1
	copy(frame[5:9], seedBytes)
	copy(frame[9:], ciphertext)
	return frame, nil
}

func DecryptLSGRecord(frame []byte, sessionKey []byte) (DecryptedLSGRecord, error) {
	if len(sessionKey) != 24 {
		return DecryptedLSGRecord{}, fmt.Errorf("LSG session key length must be 24 bytes, got %d", len(sessionKey))
	}
	record, err := ParseLSGRecord(frame)
	if err != nil {
		return DecryptedLSGRecord{}, err
	}
	result := DecryptedLSGRecord{LSGRecord: record}
	if !record.Encrypted {
		result.Plaintext = append([]byte(nil), record.Payload...)
		result.Message = append([]byte(nil), record.Payload...)
		if len(result.Message) > 0 {
			result.MessageType = result.Message[0]
		}
		return result, nil
	}

	block, err := des.NewTripleDESCipher(sessionKey)
	if err != nil {
		return DecryptedLSGRecord{}, fmt.Errorf("create LSG 3DES cipher: %w", err)
	}
	result.Plaintext = make([]byte, len(record.Payload))
	cipher.NewCBCDecrypter(block, record.IV[:]).CryptBlocks(result.Plaintext, record.Payload)
	if len(result.Plaintext) < 5 {
		return result, fmt.Errorf("decrypted LSG payload too short: %d", len(result.Plaintext))
	}
	result.HMAC = binary.LittleEndian.Uint32(result.Plaintext[:4])
	result.MessageType = result.Plaintext[4]
	result.Message = append([]byte(nil), result.Plaintext[4:]...)
	result.ExpectedHMAC = lsgHMAC(result.Plaintext[5:], sessionKey)
	result.HMACValid = hmac.Equal(result.Plaintext[:4], littleEndianUint32(result.ExpectedHMAC))
	return result, nil
}

func lsgHMAC(messageWithoutType []byte, sessionKey []byte) uint32 {
	mac := hmac.New(sha1.New, sessionKey)
	_, _ = mac.Write(messageWithoutType)
	return binary.LittleEndian.Uint32(mac.Sum(nil)[:4])
}

// LSGHMACCandidate names a hypothesis about which bytes the client MACs and how.
type LSGHMACCandidate struct {
	Name     string
	Computed uint32
	Matches  bool
}

// DiagnoseLSGRecordHMAC decrypts a frame with the given key and, without
// requiring the primary HMAC scope to validate, reports the stored MAC, the
// decrypted plaintext, and the result of several candidate MAC scopes. It is a
// diagnostic aid for reverse-engineering the exact HMAC input and is not used
// on the success path.
func DiagnoseLSGRecordHMAC(frame []byte, sessionKey []byte) (stored uint32, plaintext []byte, candidates []LSGHMACCandidate, err error) {
	record, parseErr := ParseLSGRecord(frame)
	if parseErr != nil {
		return 0, nil, nil, parseErr
	}
	if !record.Encrypted {
		return 0, nil, nil, fmt.Errorf("record is not encrypted")
	}
	block, cipherErr := des.NewTripleDESCipher(sessionKey)
	if cipherErr != nil {
		return 0, nil, nil, cipherErr
	}
	plaintext = make([]byte, len(record.Payload))
	cipher.NewCBCDecrypter(block, record.IV[:]).CryptBlocks(plaintext, record.Payload)
	if len(plaintext) < 5 {
		return 0, plaintext, nil, fmt.Errorf("decrypted plaintext too short: %d", len(plaintext))
	}
	stored = binary.LittleEndian.Uint32(plaintext[:4])

	seed := littleEndianUint32(record.IVSeed)
	mac := func(parts ...[]byte) uint32 {
		h := hmac.New(sha1.New, sessionKey)
		for _, p := range parts {
			_, _ = h.Write(p)
		}
		return binary.LittleEndian.Uint32(h.Sum(nil)[:4])
	}
	macLast4 := func(parts ...[]byte) uint32 {
		h := hmac.New(sha1.New, sessionKey)
		for _, p := range parts {
			_, _ = h.Write(p)
		}
		sum := h.Sum(nil)
		return binary.LittleEndian.Uint32(sum[len(sum)-4:])
	}

	payloadNoType := plaintext[5:]
	typeAndPayload := plaintext[4:]
	add := func(name string, computed uint32) {
		candidates = append(candidates, LSGHMACCandidate{Name: name, Computed: computed, Matches: computed == stored})
	}
	add("payload_after_type", mac(payloadNoType))
	add("type_and_payload", mac(typeAndPayload))
	add("seed+payload_after_type", mac(seed, payloadNoType))
	add("seed+type_and_payload", mac(seed, typeAndPayload))
	add("payload_after_type_last4", macLast4(payloadNoType))
	add("type_and_payload_last4", macLast4(typeAndPayload))
	return stored, plaintext, candidates, nil
}
