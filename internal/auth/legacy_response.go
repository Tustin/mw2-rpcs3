package auth

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash"

	"github.com/cxmcc/tiger"
)

const (
	legacyReplyType   = 0x13
	bdAuthNoError     = 700
	legacyTicketLen   = 128
	legacyTicketMagic = 0xefbdadde
	legacyTicketType  = 0
	legacyUserID      = 0x01100001deadc0de
	legacyUsername    = "Tustin"
)

var (
	candidateSessionKey = [24]byte{
		0x4d, 0x57, 0x32, 0x2d, 0x52, 0x50, 0x43, 0x53,
		0x33, 0x2d, 0x53, 0x45, 0x53, 0x53, 0x49, 0x4f,
		0x4e, 0x2d, 0x4b, 0x45, 0x59, 0x2d, 0x30, 0x31,
	}
)

type LegacyResponseDetails struct {
	IVSeed              uint32
	IV                  [8]byte
	SessionKey          [24]byte
	GameTicket          [legacyTicketLen]byte
	EncryptedGameTicket [legacyTicketLen]byte
	LSGTicket           [legacyTicketLen]byte
}

func BuildLegacySuccessResponse(platformKey []byte, gameID uint32) ([]byte, LegacyResponseDetails, error) {
	var sessionKey [24]byte
	if _, err := rand.Read(sessionKey[:]); err != nil {
		return nil, LegacyResponseDetails{}, fmt.Errorf("generate session key: %w", err)
	}
	var ivSeedBytes [4]byte
	if _, err := rand.Read(ivSeedBytes[:]); err != nil {
		return nil, LegacyResponseDetails{}, fmt.Errorf("generate IV seed: %w", err)
	}
	return buildLegacySuccessResponse(platformKey, gameID, sessionKey, binary.LittleEndian.Uint32(ivSeedBytes[:]))
}

func buildLegacySuccessResponse(platformKey []byte, gameID uint32, sessionKey [24]byte, ivSeed uint32) ([]byte, LegacyResponseDetails, error) {
	if len(platformKey) != 24 {
		return nil, LegacyResponseDetails{}, fmt.Errorf("platform key length must be 24 bytes, got %d", len(platformKey))
	}
	gameTicket := buildLegacyGameTicket(sessionKey[:], gameID)
	ivHash := tigerDigest(littleEndianUint32(ivSeed))

	block, err := des.NewTripleDESCipher(platformKey)
	if err != nil {
		return nil, LegacyResponseDetails{}, fmt.Errorf("create candidate 3DES cipher: %w", err)
	}
	var encrypted [legacyTicketLen]byte
	cipher.NewCBCEncrypter(block, ivHash[:des.BlockSize]).CryptBlocks(encrypted[:], gameTicket[:])

	lsgTicket := buildCandidateLSGTicket(sessionKey[:])
	payload := newLSBBitWriter(1 + 32 + 32 + legacyTicketLen*8*2 + len(sessionKey)*8)
	payload.writeBit(false)
	payload.writeBytes(littleEndianUint32(bdAuthNoError))
	payload.writeBytes(littleEndianUint32(ivSeed))
	payload.writeBytes(encrypted[:])
	payload.writeBytes(lsgTicket[:])
	payload.writeBytes(sessionKey[:])

	bodyLength := 2 + len(payload.bytes())
	response := make([]byte, 4+bodyLength)
	binary.LittleEndian.PutUint32(response[:4], uint32(bodyLength))
	response[4] = 0
	response[5] = legacyReplyType
	copy(response[6:], payload.bytes())

	var iv [8]byte
	copy(iv[:], ivHash[:des.BlockSize])
	return response, LegacyResponseDetails{
		IVSeed:              ivSeed,
		IV:                  iv,
		SessionKey:          sessionKey,
		GameTicket:          gameTicket,
		EncryptedGameTicket: encrypted,
		LSGTicket:           lsgTicket,
	}, nil
}

func buildLegacyGameTicket(sessionKey []byte, gameID uint32) [legacyTicketLen]byte {
	var ticket [legacyTicketLen]byte
	binary.LittleEndian.PutUint32(ticket[0x00:0x04], legacyTicketMagic)
	ticket[0x04] = legacyTicketType
	binary.LittleEndian.PutUint32(ticket[0x05:0x09], gameID)
	for index := 0x09; index < 0x19; index++ {
		ticket[index] = 0x0a
	}
	binary.LittleEndian.PutUint64(ticket[0x19:0x21], legacyUserID)
	copy(ticket[0x21:0x61], []byte(legacyUsername))
	copy(ticket[0x61:0x79], sessionKey)
	for index := 0x79; index < legacyTicketLen; index++ {
		ticket[index] = 0x0a
	}
	return ticket
}

func buildCandidateLSGTicket(sessionKey []byte) [legacyTicketLen]byte {
	var ticket [legacyTicketLen]byte
	copy(ticket[0x00:0x18], sessionKey)
	binary.LittleEndian.PutUint64(ticket[0x18:0x20], 0)
	binary.LittleEndian.PutUint32(ticket[0x20:0x24], 0)
	copy(ticket[0x24:0x64], []byte("Tustin"))
	return ticket
}

func tigerDigest(data []byte) []byte {
	var digest hash.Hash = tiger.New()
	_, _ = digest.Write(data)
	return digest.Sum(nil)
}

func littleEndianUint32(value uint32) []byte {
	encoded := make([]byte, 4)
	binary.LittleEndian.PutUint32(encoded, value)
	return encoded
}

type lsbBitWriter struct {
	data   []byte
	bitPos int
}

func newLSBBitWriter(capacityBits int) *lsbBitWriter {
	return &lsbBitWriter{data: make([]byte, (capacityBits+7)/8)}
}

func (w *lsbBitWriter) writeBit(value bool) {
	if value {
		w.data[w.bitPos/8] |= 1 << (w.bitPos % 8)
	}
	w.bitPos++
}

func (w *lsbBitWriter) writeBytes(data []byte) {
	for _, value := range data {
		for bit := 0; bit < 8; bit++ {
			w.writeBit(value&(1<<bit) != 0)
		}
	}
}

func (w *lsbBitWriter) bytes() []byte {
	return w.data[:(w.bitPos+7)/8]
}
