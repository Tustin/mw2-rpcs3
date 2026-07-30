package peerproto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCommonAddrLiteralGolden(t *testing.T) {
	const goldenHex = "c0a8010a020c0a000005341200ff00ff000000ff00ff000002"
	golden := decodeCommonAddrHex(t, goldenHex)
	want := CommonAddr{
		Local: [CommonAddrLocalAddressCount]Address{
			{IPv4: [4]byte{192, 168, 1, 10}, Port: 3074},
			{IPv4: [4]byte{10, 0, 0, 5}, Port: 0x1234},
			DefaultCommonAddrAddress(),
		},
		Public: DefaultCommonAddrAddress(),
		NAT:    NATTypeModerate,
	}

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("wire = %x, want literal golden %s", got, goldenHex)
	}

	parsed, err := ParseCommonAddr(golden)
	if err != nil {
		t.Fatalf("ParseCommonAddr: %v", err)
	}
	if parsed != want {
		t.Fatalf("parsed = %#v, want %#v", parsed, want)
	}
}

func TestCommonAddrPublicAddressAndPortEndian(t *testing.T) {
	const goldenHex = "c0a8010a020c00ff00ff000000ff00ff0000c633644d50c303"
	golden := decodeCommonAddrHex(t, goldenHex)

	parsed, err := ParseCommonAddr(golden)
	if err != nil {
		t.Fatalf("ParseCommonAddr: %v", err)
	}
	if parsed.Public != (Address{IPv4: [4]byte{198, 51, 100, 77}, Port: 50000}) {
		t.Fatalf("public = %#v", parsed.Public)
	}
	if parsed.NAT != NATTypeStrict {
		t.Fatalf("NAT = %d, want strict", parsed.NAT)
	}

	roundTrip, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(roundTrip, golden) {
		t.Fatalf("wire = %x, want %x", roundTrip, golden)
	}
}

func TestCommonAddrRejectsNoncanonicalWire(t *testing.T) {
	valid := decodeCommonAddrHex(t, "c0a8010a020c00ff00ff000000ff00ff0000c633644d50c302")
	tests := []struct {
		name string
		wire []byte
	}{
		{name: "empty"},
		{name: "truncated", wire: valid[:len(valid)-1]},
		{name: "trailing", wire: append(append([]byte(nil), valid...), 0)},
		{name: "NAT zero", wire: replaceCommonAddrByte(valid, 24, 0)},
		{name: "NAT four", wire: replaceCommonAddrByte(valid, 24, 4)},
		{name: "nonzero unused local port", wire: replaceCommonAddrByte(valid, 10, 1)},
		{
			name: "populated local after sentinel",
			wire: replaceCommonAddrBytes(
				replaceCommonAddrBytes(valid, 0, []byte{0x00, 0xff, 0x00, 0xff, 0, 0}),
				6,
				[]byte{10, 0, 0, 5, 0x02, 0x0c},
			),
		},
		{
			name: "nonzero public sentinel port",
			wire: replaceCommonAddrBytes(
				valid,
				18,
				[]byte{0x00, 0xff, 0x00, 0xff, 1, 0},
			),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if common, err := ParseCommonAddr(test.wire); err == nil {
				t.Fatalf("unexpected common address: %#v", common)
			}
		})
	}
}

func TestCommonAddrMarshalRejectsNoncanonicalValue(t *testing.T) {
	valid := CommonAddr{
		Local: [CommonAddrLocalAddressCount]Address{
			{IPv4: [4]byte{192, 168, 1, 10}, Port: 3074},
			DefaultCommonAddrAddress(),
			DefaultCommonAddrAddress(),
		},
		Public: DefaultCommonAddrAddress(),
		NAT:    NATTypeOpen,
	}
	tests := []struct {
		name   string
		mutate func(*CommonAddr)
	}{
		{name: "invalid NAT", mutate: func(common *CommonAddr) { common.NAT = 0 }},
		{
			name: "local gap",
			mutate: func(common *CommonAddr) {
				common.Local[0] = DefaultCommonAddrAddress()
				common.Local[1] = Address{IPv4: [4]byte{10, 0, 0, 5}, Port: 3074}
			},
		},
		{
			name:   "local sentinel port",
			mutate: func(common *CommonAddr) { common.Local[1].Port = 1 },
		},
		{
			name:   "public sentinel port",
			mutate: func(common *CommonAddr) { common.Public.Port = 1 },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			common := valid
			test.mutate(&common)
			if wire, err := common.MarshalBinary(); err == nil {
				t.Fatalf("unexpected wire: %x", wire)
			}
		})
	}
}

func TestCommonAddrEffectiveAddress(t *testing.T) {
	common := CommonAddr{
		Local: [CommonAddrLocalAddressCount]Address{
			{IPv4: [4]byte{192, 168, 1, 10}, Port: 3074},
			{IPv4: [4]byte{10, 0, 0, 5}, Port: 3075},
			DefaultCommonAddrAddress(),
		},
		Public: Address{IPv4: [4]byte{198, 51, 100, 77}, Port: 50000},
		NAT:    NATTypeModerate,
	}

	got, err := common.EffectiveAddress()
	if err != nil {
		t.Fatalf("EffectiveAddress with public: %v", err)
	}
	if got != common.Public {
		t.Fatalf("effective = %#v, want public %#v", got, common.Public)
	}

	common.Public = DefaultCommonAddrAddress()
	got, err = common.EffectiveAddress()
	if err != nil {
		t.Fatalf("EffectiveAddress with local only: %v", err)
	}
	if got != common.Local[0] {
		t.Fatalf("effective = %#v, want local zero %#v", got, common.Local[0])
	}

	common.Local[0] = DefaultCommonAddrAddress()
	common.Local[1] = DefaultCommonAddrAddress()
	got, err = common.EffectiveAddress()
	if err != nil {
		t.Fatalf("EffectiveAddress empty: %v", err)
	}
	if got != DefaultCommonAddrAddress() {
		t.Fatalf("effective = %#v, want sentinel %#v", got, DefaultCommonAddrAddress())
	}
}

func TestCommonAddrTigerIdentifierUsesEffectiveSixBytes(t *testing.T) {
	common := CommonAddr{
		Local: [CommonAddrLocalAddressCount]Address{
			{IPv4: [4]byte{192, 168, 1, 10}, Port: 3074},
			DefaultCommonAddrAddress(),
			DefaultCommonAddrAddress(),
		},
		Public: Address{IPv4: [4]byte{198, 51, 100, 77}, Port: 50000},
		NAT:    NATTypeOpen,
	}

	got, err := common.TigerIdentifier()
	if err != nil {
		t.Fatalf("TigerIdentifier: %v", err)
	}
	if want := [CommonAddrIdentifierSize]byte{0x29, 0x43, 0x86, 0x15}; got != want {
		t.Fatalf("identifier = %x, want literal Tiger golden %x", got, want)
	}

	changedOutsideInput := common
	changedOutsideInput.NAT = NATTypeStrict
	changedOutsideInput.Local[0] = Address{IPv4: [4]byte{172, 16, 0, 9}, Port: 4000}
	unchanged, err := changedOutsideInput.TigerIdentifier()
	if err != nil {
		t.Fatalf("TigerIdentifier changed outside input: %v", err)
	}
	if unchanged != got {
		t.Fatalf("identifier changed from %x to %x when only non-input fields changed", got, unchanged)
	}

	changedPublic := common
	changedPublic.Public.Port++
	changed, err := changedPublic.TigerIdentifier()
	if err != nil {
		t.Fatalf("TigerIdentifier changed public: %v", err)
	}
	if changed == got {
		t.Fatalf("identifier did not change with effective address: %x", got)
	}
}

func decodeCommonAddrHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

func replaceCommonAddrByte(source []byte, offset int, value byte) []byte {
	result := append([]byte(nil), source...)
	result[offset] = value
	return result
}

func replaceCommonAddrBytes(source []byte, offset int, value []byte) []byte {
	result := append([]byte(nil), source...)
	copy(result[offset:], value)
	return result
}
