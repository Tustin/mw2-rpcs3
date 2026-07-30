package peerproto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestQoSRequestLiteralGolden(t *testing.T) {
	const goldenHex = "28080706050403020144332211d4c3b2a1"
	golden := mustDecodeHex(t, goldenHex)
	want := QoSRequest{
		Timestamp:  0x0102030405060708,
		ProbeID:    0x11223344,
		SecurityID: 0xa1b2c3d4,
	}

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("packet = %x, want literal golden %s", got, goldenHex)
	}

	parsed, err := ParseQoSRequest(golden)
	if err != nil {
		t.Fatalf("ParseQoSRequest: %v", err)
	}
	if parsed != want {
		t.Fatalf("parsed = %#v, want %#v", parsed, want)
	}
}

func TestShrinkSecurityIDUsesFirstFourRawBytes(t *testing.T) {
	securityID := mustDecodeHex(t, "d4c3b2a155667788")
	got, err := ShrinkSecurityID(securityID)
	if err != nil {
		t.Fatalf("ShrinkSecurityID: %v", err)
	}
	if got != 0xa1b2c3d4 {
		t.Fatalf("short security ID = %#x, want %#x", got, uint32(0xa1b2c3d4))
	}

	for _, invalid := range [][]byte{nil, make([]byte, 7), make([]byte, 9)} {
		if value, err := ShrinkSecurityID(invalid); err == nil {
			t.Fatalf("accepted %d-byte security ID: %#x", len(invalid), value)
		}
	}
}

func TestQoSRequestRejectsMalformedPackets(t *testing.T) {
	golden := mustDecodeHex(t, "28080706050403020144332211d4c3b2a1")
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty"},
		{name: "truncated", packet: golden[:len(golden)-1]},
		{name: "trailing", packet: append(append([]byte(nil), golden...), 0)},
		{name: "reply type", packet: append([]byte{QoSReplyType}, golden[1:]...)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if request, err := ParseQoSRequest(test.packet); err == nil {
				t.Fatalf("unexpected request: %#v", request)
			}
		})
	}
}

func TestQoSReplyLiteralGolden(t *testing.T) {
	const goldenHex = "294433221108070605040302010103000000aabbcc"
	golden := mustDecodeHex(t, goldenHex)
	want := QoSReply{
		ProbeID:   0x11223344,
		Timestamp: 0x0102030405060708,
		Enabled:   true,
		Data:      []byte{0xaa, 0xbb, 0xcc},
	}

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("packet = %x, want literal golden %s", got, goldenHex)
	}

	parsed, err := ParseQoSReply(golden)
	if err != nil {
		t.Fatalf("ParseQoSReply: %v", err)
	}
	if parsed.ProbeID != want.ProbeID ||
		parsed.Timestamp != want.Timestamp ||
		parsed.Enabled != want.Enabled ||
		!bytes.Equal(parsed.Data, want.Data) {
		t.Fatalf("parsed = %#v, want %#v", parsed, want)
	}
}

func TestQoSReplyDisabledEmptyLiteralGolden(t *testing.T) {
	const goldenHex = "294433221108070605040302010000000000"
	golden := mustDecodeHex(t, goldenHex)

	parsed, err := ParseQoSReply(golden)
	if err != nil {
		t.Fatalf("ParseQoSReply: %v", err)
	}
	if parsed.Enabled || len(parsed.Data) != 0 {
		t.Fatalf("parsed = %#v, want disabled reply with empty data", parsed)
	}

	roundTrip, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(roundTrip, golden) {
		t.Fatalf("packet = %x, want literal golden %s", roundTrip, goldenHex)
	}
}

func TestQoSReplyDoesNotAliasInputOrData(t *testing.T) {
	wire := mustDecodeHex(t, "294433221108070605040302010103000000aabbcc")
	parsed, err := ParseQoSReply(wire)
	if err != nil {
		t.Fatalf("ParseQoSReply: %v", err)
	}
	wire[len(wire)-1] = 0
	if !bytes.Equal(parsed.Data, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("parsed data changed with input: %x", parsed.Data)
	}

	data := []byte{1, 2, 3}
	packet, err := (QoSReply{Data: data}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	data[0] = 9
	if packet[QoSReplyHeaderSize] != 1 {
		t.Fatalf("marshaled packet aliases reply data: %x", packet)
	}
}

func TestQoSReplyRejectsMalformedPackets(t *testing.T) {
	golden := mustDecodeHex(t, "294433221108070605040302010103000000aabbcc")
	wrongType := append([]byte(nil), golden...)
	wrongType[0] = QoSRequestType
	invalidBool := append([]byte(nil), golden...)
	invalidBool[13] = 2
	declaredTooSmall := append([]byte(nil), golden...)
	declaredTooSmall[14] = 2
	declaredTooLarge := append([]byte(nil), golden...)
	declaredTooLarge[14] = 4
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty"},
		{name: "header truncated", packet: golden[:QoSReplyHeaderSize-1]},
		{name: "wrong type", packet: wrongType},
		{name: "invalid enabled boolean", packet: invalidBool},
		{name: "declared data too small", packet: declaredTooSmall},
		{name: "declared data too large", packet: declaredTooLarge},
		{name: "data truncated", packet: golden[:len(golden)-1]},
		{name: "trailing data", packet: append(append([]byte(nil), golden...), 0)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if reply, err := ParseQoSReply(test.packet); err == nil {
				t.Fatalf("unexpected reply: %#v", reply)
			}
		})
	}
}

func TestQoSReplyEnforcesMW2PacketLimit(t *testing.T) {
	atLimit := QoSReply{Data: make([]byte, QoSReplyMaxDataSize)}
	packet, err := atLimit.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary at limit: %v", err)
	}
	if len(packet) != QoSMaxPacketSize {
		t.Fatalf("packet size = %d, want %d", len(packet), QoSMaxPacketSize)
	}
	if _, err := ParseQoSReply(packet); err != nil {
		t.Fatalf("ParseQoSReply at limit: %v", err)
	}

	overLimit := QoSReply{Data: make([]byte, QoSReplyMaxDataSize+1)}
	if packet, err := overLimit.MarshalBinary(); err == nil {
		t.Fatalf("MarshalBinary accepted oversized reply: %d bytes", len(packet))
	}

	oversizedWire := make([]byte, QoSMaxPacketSize+1)
	oversizedWire[0] = QoSReplyType
	oversizedWire[13] = 1
	oversizedWire[14] = byte((QoSReplyMaxDataSize + 1) & 0xff)
	oversizedWire[15] = byte((QoSReplyMaxDataSize + 1) >> 8)
	if reply, err := ParseQoSReply(oversizedWire); err == nil {
		t.Fatalf("ParseQoSReply accepted oversized reply: %#v", reply)
	}
}

func TestNATTraversalLiteralGoldenAndHMAC(t *testing.T) {
	// Secret bytes are the literal sequence 00, 01, ..., 1b. The expected HMAC
	// was independently calculated over:
	//   44332211 c000020a3412 c6336414020c
	const goldenHex = "0a020059af9ba1cf59b8067f3f44332211c000020a3412c6336414020c"
	golden := mustDecodeHex(t, goldenHex)
	secret := sequenceSecret()
	want := NATTraversalPacket{
		Type:            NATTraversalType0A,
		ProtocolVersion: NATTraversalProtocolVersion,
		HMAC:            [NATTraversalHMACSize]byte{0x59, 0xaf, 0x9b, 0xa1, 0xcf, 0x59, 0xb8, 0x06, 0x7f, 0x3f},
		Identifier:      0x11223344,
		Source:          Address{IPv4: [4]byte{192, 0, 2, 10}, Port: 0x1234},
		Destination:     Address{IPv4: [4]byte{198, 51, 100, 20}, Port: 3074},
	}

	calculated, err := CalculateNATTraversalHMAC(secret, want.Identifier, want.Source, want.Destination)
	if err != nil {
		t.Fatalf("CalculateNATTraversalHMAC: %v", err)
	}
	if calculated != want.HMAC {
		t.Fatalf("HMAC = %x, want independent literal %x", calculated, want.HMAC)
	}

	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(wire, golden) {
		t.Fatalf("packet = %x, want literal golden %s", wire, goldenHex)
	}

	parsed, err := ParseNATTraversalPacket(golden)
	if err != nil {
		t.Fatalf("ParseNATTraversalPacket: %v", err)
	}
	if parsed != want {
		t.Fatalf("parsed = %#v, want %#v", parsed, want)
	}
	valid, err := VerifyNATTraversalHMAC(secret, parsed)
	if err != nil {
		t.Fatalf("VerifyNATTraversalHMAC: %v", err)
	}
	if !valid {
		t.Fatal("literal golden HMAC was rejected")
	}
}

func TestNATTraversalAllTypesAndLaterVersionRoundTrip(t *testing.T) {
	for _, packetType := range []byte{
		NATTraversalType0A,
		NATTraversalType0B,
		NATTraversalType0C,
		NATTraversalType0D,
	} {
		t.Run(hex.EncodeToString([]byte{packetType}), func(t *testing.T) {
			want := NATTraversalPacket{
				Type:            packetType,
				ProtocolVersion: 3,
				HMAC:            [NATTraversalHMACSize]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
				Identifier:      0xfedcba98,
				Source:          Address{IPv4: [4]byte{127, 0, 0, 1}, Port: 3074},
				Destination:     Address{IPv4: [4]byte{203, 0, 113, 9}, Port: 65535},
			}
			wire, err := want.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			got, err := ParseNATTraversalPacket(wire)
			if err != nil {
				t.Fatalf("ParseNATTraversalPacket: %v", err)
			}
			if got != want {
				t.Fatalf("round trip = %#v, want %#v", got, want)
			}
		})
	}
}

func TestNATTraversalRejectsMalformedPackets(t *testing.T) {
	golden := mustDecodeHex(t, "0a020059af9ba1cf59b8067f3f44332211c000020a3412c6336414020c")
	badLowType := append([]byte(nil), golden...)
	badLowType[0] = NATTraversalType0A - 1
	badHighType := append([]byte(nil), golden...)
	badHighType[0] = NATTraversalType0D + 1
	oldVersion := append([]byte(nil), golden...)
	oldVersion[1], oldVersion[2] = 1, 0
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty"},
		{name: "truncated", packet: golden[:len(golden)-1]},
		{name: "trailing", packet: append(append([]byte(nil), golden...), 0)},
		{name: "type below range", packet: badLowType},
		{name: "type above range", packet: badHighType},
		{name: "version one", packet: oldVersion},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if packet, err := ParseNATTraversalPacket(test.packet); err == nil {
				t.Fatalf("unexpected packet: %#v", packet)
			}
		})
	}
}

func TestNATTraversalMarshalRejectsInvalidMetadata(t *testing.T) {
	valid := NATTraversalPacket{
		Type:            NATTraversalType0A,
		ProtocolVersion: NATTraversalProtocolVersion,
	}
	badType := valid
	badType.Type = 0xff
	if wire, err := badType.MarshalBinary(); err == nil {
		t.Fatalf("unexpected packet for invalid type: %x", wire)
	}

	oldVersion := valid
	oldVersion.ProtocolVersion = 1
	if wire, err := oldVersion.MarshalBinary(); err == nil {
		t.Fatalf("unexpected packet for old version: %x", wire)
	}
}

func TestNATTraversalHMACRejectsWrongSecretSizeAndTampering(t *testing.T) {
	packet, err := ParseNATTraversalPacket(mustDecodeHex(t, "0a020059af9ba1cf59b8067f3f44332211c000020a3412c6336414020c"))
	if err != nil {
		t.Fatalf("ParseNATTraversalPacket: %v", err)
	}

	for _, size := range []int{0, NATTraversalSecretSize - 1, NATTraversalSecretSize + 1} {
		t.Run(hex.EncodeToString([]byte{byte(size)}), func(t *testing.T) {
			if _, err := CalculateNATTraversalHMAC(make([]byte, size), packet.Identifier, packet.Source, packet.Destination); err == nil {
				t.Fatalf("CalculateNATTraversalHMAC accepted %d-byte secret", size)
			}
			if valid, err := VerifyNATTraversalHMAC(make([]byte, size), packet); err == nil {
				t.Fatalf("VerifyNATTraversalHMAC accepted %d-byte secret, valid=%v", size, valid)
			}
		})
	}

	tampered := packet
	tampered.Destination.Port++
	valid, err := VerifyNATTraversalHMAC(sequenceSecret(), tampered)
	if err != nil {
		t.Fatalf("VerifyNATTraversalHMAC: %v", err)
	}
	if valid {
		t.Fatal("tampered packet passed HMAC verification")
	}

	tampered = packet
	tampered.HMAC[0] ^= 0x80
	valid, err = VerifyNATTraversalHMAC(sequenceSecret(), tampered)
	if err != nil {
		t.Fatalf("VerifyNATTraversalHMAC: %v", err)
	}
	if valid {
		t.Fatal("tampered HMAC passed verification")
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("DecodeString(%q): %v", value, err)
	}
	return decoded
}

func sequenceSecret() []byte {
	secret := make([]byte, NATTraversalSecretSize)
	for index := range secret {
		secret[index] = byte(index)
	}
	return secret
}
