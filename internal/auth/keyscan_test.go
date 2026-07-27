package auth

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/cxmcc/tiger"
)

func TestScanCapturedExchangeForLSGKey(t *testing.T) {
	response := capturedMW2SuccessResponse
	request := mustDecodeHex("3c01000000121170f7b92002a50000402c0100002101000000000124300000d8000800145a8bad4ba9fc87d2cd55e5080675f9bddf834f490001000400000100000700080000019fa07ee954000700080000019fa5a542b800020008007f60e5903c57fe000400207370656564793432346b6579000000000000000000000000000000000000000000080004757300010004000462350000000800185550303030322d424c555333303337375f30300000000000000100042e00020000080030739b1bd0eecc3aa6be052214427a7705c13869db7576c42bcebce08d8cb3f047d063bfb69f1d4473f5fa3aca0adf866f000000000000000030020044000800045a6f55a0000800383035021900885b135821f64e3ee48de6b114c3e25b8ed681b7f5a41a220218555a271356cfd310ac1ddbf0096f4d9f548740d4fdfaa69c00")
	clientLSG := mustDecodeHex("b4000000ffff00008c0000000007112805000042113e2d03b95caa2cd10db9269e48e76a14e876fc1af3e4da0bb8e7d946fdcab0d66895649b765d038575223dc67fdbddd47dafb5ec2a1f9fc785bbf449d0d9670616113138663b9c645c52d8d6db7bc6a436550e623644fc3b674325fce0d6373bed997e50b9daf953009edba3d7d33c7b63dba7b8a20b76e98ae17caeb0f92102506f06")
	clientFragments := mustDecodeHex("1d000000010000000026eef55ffbf465965a9f9c7a6cd7caa45be16a2d50d694f71d00000001010000000461e01229ec491edfb67b07396d5b34393c53a6513a210e1d00000001020000008d6091f53d7f0d04247c388f80b930080ac7e62870dd8020250000000103000000f4c28bf838b1e6e056ac23bb55dd7e50bcbed97f9eb04c26c499e87cb486e851")
	frame := mustDecodeHex(capturedLSGKeyResponseHex)

	for name, source := range map[string][]byte{"response": response, "request": request, "client_lsg": clientLSG, "client_fragments": clientFragments} {
		for offset := 0; offset+24 <= len(source); offset++ {
			candidates := map[string][]byte{
				"raw": source[offset : offset+24],
				"tiger8": tigerKey(source[offset : offset+8]),
				"tiger16": tigerKey(source[offset : offset+16]),
				"tiger24": tigerKey(source[offset : offset+24]),
			}
			for transform, key := range candidates {
				if validCapturedLSGKey(frame, key) {
					fmt.Printf("MATCH %s offset=%d transform=%s source=%x key=%x\n", name, offset, transform, source[offset:offset+24], key)
				}
			}
		}
	}
}

func tigerKey(source []byte) []byte {
	hash := tiger.New()
	_, _ = hash.Write(source)
	return hash.Sum(nil)
}

func validCapturedLSGKey(frame, key []byte) bool {
	seed := binary.LittleEndian.Uint32(frame[5:9])
	iv := tigerDigest(littleEndianUint32(seed))[:des.BlockSize]
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return false
	}
	plaintext := make([]byte, len(frame)-9)
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, frame[9:])
	if len(plaintext) < 5 {
		return false
	}
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(plaintext[5:])
	expected := binary.LittleEndian.Uint32(mac.Sum(nil)[:4])
	return binary.LittleEndian.Uint32(plaintext[:4]) == expected
}
