package auth

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"testing"
)

func TestDeriveCapturedLSGSessionKey(t *testing.T) {
	t.Skip("exploratory capture-key derivation; captured authorization ticket is not the matching platform key")
	request := mustDecodeHex("3c01000000121170f7b92002a50000402c0100002101000000000124300000d8000800145a8bad4ba9fc87d2cd55e5080675f9bddf834f490001000400000100000700080000019fa07ee954000700080000019fa5a542b800020008007f60e5903c57fe000400207370656564793432346b6579000000000000000000000000000000000000000000080004757300010004000462350000000800185550303030322d424c555333303337375f30300000000000000100042e00020000080030739b1bd0eecc3aa6be052214427a7705c13869db7576c42bcebce08d8cb3f047d063bfb69f1d4473f5fa3aca0adf866f000000000000000030020044000800045a6f55a0000800383035021900885b135821f64e3ee48de6b114c3e25b8ed681b7f5a41a220218555a271356cfd310ac1ddbf0096f4d9f548740d4fdfaa69c00")
	parsedRequest, err := ParseRetailAuthRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	response, err := ParseLegacySuccessResponse(capturedMW2SuccessResponse)
	if err != nil {
		t.Fatal(err)
	}
	iv := tigerDigest(littleEndianUint32(response.IVSeed))[:des.BlockSize]
	for offset := 0; offset+24 <= len(parsedRequest.Ticket); offset++ {
		platformKey := parsedRequest.Ticket[offset : offset+24]
		block, cipherErr := des.NewTripleDESCipher(platformKey)
		if cipherErr != nil {
			continue
		}
		var gameTicket [legacyTicketLen]byte
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(gameTicket[:], response.EncryptedGameTicket[:])
		if binary.LittleEndian.Uint32(gameTicket[:4]) != legacyTicketMagic {
			continue
		}
		var key [24]byte
		copy(key[:], gameTicket[0x61:0x79])
		decrypted, decryptErr := DecryptLSGRecord(mustDecodeHex(capturedLSGKeyResponseHex), key[:])
		if decryptErr != nil {
			t.Fatal(decryptErr)
		}
		t.Logf("offset=%d platform=%x key=%x client=%x type=%02x hmac=%t message=%x", offset, platformKey, key, response.SessionKey, decrypted.MessageType, decrypted.HMACValid, decrypted.Message)
		if !decrypted.HMACValid {
			t.Fatal("derived key did not validate captured LSG response")
		}
		if bytes.Equal(key[:], response.SessionKey[:]) {
			t.Fatal("LSG key unexpectedly equals the explicit client session key")
		}
		return
	}
	t.Fatal("no 24-byte authorization-ticket window decrypted the captured game ticket")
}
