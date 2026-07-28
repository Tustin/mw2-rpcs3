package peerproto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

const (
	dtlsInitGoldenHex    = "01020000000066550001020304050607"
	dtlsInitAckGoldenHex = "" +
		"0202ccbb0000" + // 00: verification=initiator tag, sequence=zero
		"88776655" + // 06: timestamp
		"a0a1a2a3" + // 10: raw cookie signature
		"aa99aa99" + // 14: responder tag and its duplicate
		"ccbbeedd100f" + // 18: initiator tag, tie A, tie B
		"c0000209020c" + // 24: 192.0.2.9:3074
		"1011121314151617" // 30: raw Blob8
	dtlsCookieEchoGoldenHex = "" +
		"0302aa990000" + // 000: verification=responder tag, sequence=zero
		dtlsInitAckGoldenHex + // 006: complete nested InitAck
		"202122232425262728292a2b2c2d2e2f303132333435363738" + // 044: CommonAddr25
		"4041424344454647" + // 069: raw Blob8
		"808182838485868788898a8b8c8d8e8f" + // 077: ECC public key
		"909192939495969798999a9b9c9d9e9f" +
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
		"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
		"e0e1e2e3"
	dtlsCookieAckGoldenHex = "" +
		"040232310000" + // 000: sequence=zero; verification uses external state
		"808182838485868788898a8b8c8d8e8f" + // 006: ECC public key
		"909192939495969798999a9b9c9d9e9f" +
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
		"b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
		"e0e1e2e3" +
		"f0f1f2f3f4f5f6f7" // 106: raw Blob8
	dtlsErrorGoldenHex = "" +
		"050278560000" + // verification=0x5678, sequence=zero
		"00" + // bad security identifier
		"0001020304050607"
	dtlsDataGoldenHex = "" +
		"060234120100" + // verification=0x1234, sequence=1
		"c78a7331a9b5b6f2" + // leading 8 bytes of HMAC-SHA1
		"0500" + // five-byte transformed prefix
		"cebcacfc15141716" + // prefix + 0x01 padding, XOR Blob8
		"aabbcc" // clear tail
)

func TestDTLSPacketTypeConstants(t *testing.T) {
	got := [6]byte{
		DTLSTypeInit,
		DTLSTypeInitAck,
		DTLSTypeCookieEcho,
		DTLSTypeCookieAck,
		DTLSTypeError,
		DTLSTypeData,
	}
	want := [6]byte{1, 2, 3, 4, 5, 6}
	if got != want {
		t.Fatalf("bdDTLS packet types = %v, want %v", got, want)
	}
}

func TestDTLSInitLiteralGolden(t *testing.T) {
	golden := decodeDTLSGolden(t, dtlsInitGoldenHex, DTLSInitSize)
	want := DTLSInit{
		Header:             DTLSHeader{},
		InitiatorLocalTag:  0x5566,
		SecurityIdentifier: dtlsBlob8(0x00),
	}

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("Init = %x, want literal golden %s", got, dtlsInitGoldenHex)
	}

	parsed, err := ParseDTLSInit(golden)
	if err != nil {
		t.Fatalf("ParseDTLSInit: %v", err)
	}
	if parsed != want {
		t.Fatalf("Init = %#v, want %#v", parsed, want)
	}
}

func TestDTLSInitAckLiteralGolden(t *testing.T) {
	golden := decodeDTLSGolden(t, dtlsInitAckGoldenHex, DTLSInitAckSize)
	want := dtlsInitAckFixture()

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("InitAck = %x, want literal golden %s", got, dtlsInitAckGoldenHex)
	}

	parsed, err := ParseDTLSInitAck(golden)
	if err != nil {
		t.Fatalf("ParseDTLSInitAck: %v", err)
	}
	if parsed != want {
		t.Fatalf("InitAck = %#v, want %#v", parsed, want)
	}
}

func TestDTLSCookieEchoLiteralGolden(t *testing.T) {
	golden := decodeDTLSGolden(t, dtlsCookieEchoGoldenHex, DTLSCookieEchoSize)
	want := DTLSCookieEcho{
		Header:        DTLSHeader{VerificationTag: 0x99aa},
		InitAck:       dtlsInitAckFixture(),
		CommonAddress: dtlsCommonAddress(0x20),
		Blob:          dtlsBlob8(0x40),
		PublicKey:     dtlsPublicKey(0x80),
	}

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("CookieEcho = %x, want literal golden %s", got, dtlsCookieEchoGoldenHex)
	}

	parsed, err := ParseDTLSCookieEcho(golden)
	if err != nil {
		t.Fatalf("ParseDTLSCookieEcho: %v", err)
	}
	if parsed != want {
		t.Fatalf("CookieEcho = %#v, want %#v", parsed, want)
	}
}

func TestDTLSCookieAckLiteralGolden(t *testing.T) {
	golden := decodeDTLSGolden(t, dtlsCookieAckGoldenHex, DTLSCookieAckSize)
	want := DTLSCookieAck{
		Header:    DTLSHeader{VerificationTag: 0x3132},
		PublicKey: dtlsPublicKey(0x80),
		Blob:      dtlsBlob8(0xf0),
	}

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("CookieAck = %x, want literal golden %s", got, dtlsCookieAckGoldenHex)
	}

	parsed, err := ParseDTLSCookieAck(golden)
	if err != nil {
		t.Fatalf("ParseDTLSCookieAck: %v", err)
	}
	if parsed != want {
		t.Fatalf("CookieAck = %#v, want %#v", parsed, want)
	}
}

func TestDTLSErrorLiteralGolden(t *testing.T) {
	golden := decodeDTLSGolden(t, dtlsErrorGoldenHex, DTLSErrorSize)
	want := DTLSError{
		Header:             DTLSHeader{VerificationTag: 0x5678},
		ErrorType:          DTLSErrorBadSecurityID,
		SecurityIdentifier: dtlsBlob8(0),
	}

	got, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("Error = %x, want literal golden %s", got, dtlsErrorGoldenHex)
	}

	parsed, err := ParseDTLSError(golden)
	if err != nil {
		t.Fatalf("ParseDTLSError: %v", err)
	}
	if parsed != want {
		t.Fatalf("Error = %#v, want %#v", parsed, want)
	}
}

func TestDTLSDataLiteralGolden(t *testing.T) {
	sessionKey := dtlsSessionKey()
	securityIdentifier := dtlsBlob8(0x10)
	golden := decodeDTLSGolden(t, dtlsDataGoldenHex, 27)
	want := DTLSData{
		Header:      DTLSHeader{VerificationTag: 0x1234, SequenceTag: 1},
		TitlePacket: decodeDTLSGolden(t, "0500deadbeef01aabbcc", 10),
	}

	got, err := want.MarshalAuthenticated(sessionKey, securityIdentifier)
	if err != nil {
		t.Fatalf("MarshalAuthenticated: %v", err)
	}
	if !bytes.Equal(got, golden) {
		t.Fatalf("Data = %x, want literal golden %s", got, dtlsDataGoldenHex)
	}

	parsed, err := ParseDTLSData(golden, sessionKey, securityIdentifier)
	if err != nil {
		t.Fatalf("ParseDTLSData: %v", err)
	}
	if parsed.Header != want.Header || !bytes.Equal(parsed.TitlePacket, want.TitlePacket) {
		t.Fatalf("Data = %#v, want %#v", parsed, want)
	}
}

func TestDTLSDataAuthenticationCoverageAndTampering(t *testing.T) {
	sessionKey := dtlsSessionKey()
	securityIdentifier := dtlsBlob8(0x10)
	golden := decodeDTLSGolden(t, dtlsDataGoldenHex, 27)

	coveredOffsets := map[string]int{
		"verification tag": 2,
		"sequence tag":     4,
		"stored MAC":       6,
		"transformed data": 16,
		"padding":          21,
		"clear tail":       24,
	}
	for name, offset := range coveredOffsets {
		t.Run(name, func(t *testing.T) {
			tampered := replaceDTLSByte(golden, offset, golden[offset]^1)
			if _, err := ParseDTLSData(
				tampered,
				sessionKey,
				securityIdentifier,
			); !errors.Is(err, ErrDTLSDataAuthentication) {
				t.Fatalf("tamper error = %v, want authentication failure", err)
			}
		})
	}

	t.Run("encrypted length is deliberately uncovered", func(t *testing.T) {
		tampered := replaceDTLSByte(golden, 14, 6)
		got, err := ParseDTLSData(tampered, sessionKey, securityIdentifier)
		if err != nil {
			t.Fatalf("ParseDTLSData: %v", err)
		}
		want := decodeDTLSGolden(t, "0600deadbeef0101aabbcc", 11)
		if !bytes.Equal(got.TitlePacket, want) {
			t.Fatalf("decoded title packet = %x, want %x", got.TitlePacket, want)
		}
	})

	t.Run("uncovered length still receives bounds validation", func(t *testing.T) {
		tampered := replaceDTLSByte(golden, 15, 1)
		if _, err := ParseDTLSData(
			tampered,
			sessionKey,
			securityIdentifier,
		); err == nil {
			t.Fatal("accepted out-of-bounds encrypted prefix")
		}
	})
}

func TestDTLSDataRejectsInvalidInputs(t *testing.T) {
	sessionKey := dtlsSessionKey()
	securityIdentifier := dtlsBlob8(0x10)
	valid := DTLSData{
		Header:      DTLSHeader{VerificationTag: 0x1234, SequenceTag: 1},
		TitlePacket: decodeDTLSGolden(t, "0000", 2),
	}

	for _, keySize := range []int{DTLSSessionKeySize - 1, DTLSSessionKeySize + 1} {
		t.Run(fmt.Sprintf("key size %d", keySize), func(t *testing.T) {
			if _, err := valid.MarshalAuthenticated(
				make([]byte, keySize),
				securityIdentifier,
			); err == nil {
				t.Fatal("accepted invalid session key")
			}
			if _, err := ParseDTLSData(
				make([]byte, DTLSDataFixedSize),
				make([]byte, keySize),
				securityIdentifier,
			); err == nil {
				t.Fatal("parser accepted invalid session key")
			}
		})
	}

	t.Run("missing title length", func(t *testing.T) {
		packet := valid
		packet.TitlePacket = []byte{0}
		if _, err := packet.MarshalAuthenticated(
			sessionKey,
			securityIdentifier,
		); err == nil {
			t.Fatal("accepted title packet without its length field")
		}
	})

	t.Run("prefix past title payload", func(t *testing.T) {
		packet := valid
		packet.TitlePacket = []byte{2, 0, 0xaa}
		if _, err := packet.MarshalAuthenticated(
			sessionKey,
			securityIdentifier,
		); err == nil {
			t.Fatal("accepted encrypted prefix past title payload")
		}
	})

	t.Run("maximum sender packet", func(t *testing.T) {
		packet := valid
		packet.TitlePacket = make([]byte, DTLSDataMaxTitleSize)
		packet.TitlePacket[0] = 1
		wire, err := packet.MarshalAuthenticated(sessionKey, securityIdentifier)
		if err != nil {
			t.Fatalf("MarshalAuthenticated: %v", err)
		}
		if len(wire) != DTLSDataMaxWireSize {
			t.Fatalf("wire size = %#x, want %#x", len(wire), DTLSDataMaxWireSize)
		}
		parsed, err := ParseDTLSData(wire, sessionKey, securityIdentifier)
		if err != nil {
			t.Fatalf("ParseDTLSData at canonical maximum: %v", err)
		}
		if !bytes.Equal(parsed.TitlePacket, packet.TitlePacket) {
			t.Fatal("maximum-size title packet did not round trip")
		}

		oversizedWire := append(append([]byte(nil), wire...), 0)
		copy(oversizedWire[6:14], authenticateDTLSData(oversizedWire, sessionKey))
		if _, err := ParseDTLSData(
			oversizedWire,
			sessionKey,
			securityIdentifier,
		); err == nil {
			t.Fatal("parser accepted authenticated wire packet above canonical maximum")
		}

		packet.TitlePacket = append(packet.TitlePacket, 0)
		if _, err := packet.MarshalAuthenticated(
			sessionKey,
			securityIdentifier,
		); err == nil {
			t.Fatal("accepted title packet above sender maximum")
		}
	})
}

func TestDTLSReplayWindowBoundaries(t *testing.T) {
	t.Run("forward jump reset, reorder, duplicate", func(t *testing.T) {
		var window DTLSReplayWindow
		if sequence, err := window.CheckAndMark(1); err != nil || sequence != 1 {
			t.Fatalf("first sequence = %d, %v", sequence, err)
		}
		if sequence, err := window.CheckAndMark(40); err != nil || sequence != 40 {
			t.Fatalf("forward sequence = %d, %v", sequence, err)
		}
		if window.bitmap != 1 {
			t.Fatalf("bitmap after large jump = %#08x, want 1", window.bitmap)
		}
		if sequence, err := window.CheckAndMark(39); err != nil || sequence != 39 {
			t.Fatalf("reordered sequence = %d, %v", sequence, err)
		}
		if _, err := window.CheckAndMark(39); !errors.Is(err, ErrDTLSReplayDuplicate) {
			t.Fatalf("duplicate error = %v", err)
		}
	})

	t.Run("age 31 accepted, age 32 rejected", func(t *testing.T) {
		var window DTLSReplayWindow
		if _, err := window.CheckAndMark(100); err != nil {
			t.Fatal(err)
		}
		if _, err := window.CheckAndMark(69); err != nil {
			t.Fatalf("age 31: %v", err)
		}
		if _, err := window.CheckAndMark(68); !errors.Is(err, ErrDTLSReplayTooOld) {
			t.Fatalf("age 32 error = %v", err)
		}
	})

	t.Run("signed backward expansion across zero", func(t *testing.T) {
		var window DTLSReplayWindow
		if sequence, err := window.CheckAndMark(0); err != nil || sequence != 0 {
			t.Fatalf("first sequence = %#08x, %v", sequence, err)
		}
		sequence, err := window.CheckAndMark(0xffff)
		if err != nil || sequence != 0xffffffff {
			t.Fatalf("backward sequence = %#08x, %v; want %#08x", sequence, err, uint32(0xffffffff))
		}
		if window.highest != 0 {
			t.Fatalf("backward packet moved highest to %#08x, want zero", uint32(window.highest))
		}
		if _, err := window.CheckAndMark(0xffff); !errors.Is(err, ErrDTLSReplayDuplicate) {
			t.Fatalf("backward duplicate error = %v", err)
		}
		if sequence, err := window.CheckAndMark(1); err != nil || sequence != 1 {
			t.Fatalf("next sequence = %#08x, %v", sequence, err)
		}
	})

	t.Run("16-bit wrap", func(t *testing.T) {
		var window DTLSReplayWindow
		for _, test := range []struct {
			wire uint16
			full uint32
		}{
			{wire: 0xfffe, full: 0xfffe},
			{wire: 0xffff, full: 0xffff},
			{wire: 0x0000, full: 0x10000},
		} {
			got, err := window.CheckAndMark(test.wire)
			if err != nil || got != test.full {
				t.Fatalf("sequence %#04x = %#08x, %v; want %#08x", test.wire, got, err, test.full)
			}
		}
	})

	t.Run("exact half-range remains in current base", func(t *testing.T) {
		var window DTLSReplayWindow
		if _, err := window.CheckAndMark(0); err != nil {
			t.Fatal(err)
		}
		got, err := window.CheckAndMark(0x8000)
		if err != nil || got != 0x8000 {
			t.Fatalf("half-range sequence = %#08x, %v; want %#08x", got, err, uint32(0x8000))
		}
	})
}

func TestDTLSDataAuthenticationAndTagPrecedeReplay(t *testing.T) {
	sessionKey := dtlsSessionKey()
	securityIdentifier := dtlsBlob8(0x10)
	packet := DTLSData{
		Header:      DTLSHeader{VerificationTag: 0x1234, SequenceTag: 2},
		TitlePacket: decodeDTLSGolden(t, "0000aabb", 4),
	}
	valid, err := packet.MarshalAuthenticated(sessionKey, securityIdentifier)
	if err != nil {
		t.Fatal(err)
	}

	var window DTLSReplayWindow
	tampered := replaceDTLSByte(valid, 6, valid[6]^1)
	if _, _, err := ParseDTLSDataWithReplay(
		tampered,
		sessionKey,
		securityIdentifier,
		0x1234,
		&window,
	); !errors.Is(err, ErrDTLSDataAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}
	if window.initialized {
		t.Fatal("authentication failure consumed a replay sequence")
	}

	wrongAssociation := packet
	wrongAssociation.Header.VerificationTag = 0x9999
	wrongWire, err := wrongAssociation.MarshalAuthenticated(sessionKey, securityIdentifier)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseDTLSDataWithReplay(
		wrongWire,
		sessionKey,
		securityIdentifier,
		0x1234,
		&window,
	); !errors.Is(err, ErrDTLSVerificationTag) {
		t.Fatalf("verification error = %v", err)
	}
	if window.initialized {
		t.Fatal("verification-tag failure consumed a replay sequence")
	}

	got, fullSequence, err := ParseDTLSDataWithReplay(
		valid,
		sessionKey,
		securityIdentifier,
		0x1234,
		&window,
	)
	if err != nil {
		t.Fatalf("valid packet: %v", err)
	}
	if fullSequence != 2 || !bytes.Equal(got.TitlePacket, packet.TitlePacket) {
		t.Fatalf("parsed packet = %#v, sequence %d", got, fullSequence)
	}
	if _, _, err := ParseDTLSDataWithReplay(
		valid,
		sessionKey,
		securityIdentifier,
		0x1234,
		&window,
	); !errors.Is(err, ErrDTLSReplayDuplicate) {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestDTLSParsersRejectMalformedFraming(t *testing.T) {
	tests := []struct {
		name         string
		goldenHex    string
		expectedSize int
		expectedType byte
		parse        func([]byte) error
	}{
		{
			name:         "Init",
			goldenHex:    dtlsInitGoldenHex,
			expectedSize: DTLSInitSize,
			expectedType: DTLSTypeInit,
			parse: func(wire []byte) error {
				_, err := ParseDTLSInit(wire)
				return err
			},
		},
		{
			name:         "InitAck",
			goldenHex:    dtlsInitAckGoldenHex,
			expectedSize: DTLSInitAckSize,
			expectedType: DTLSTypeInitAck,
			parse: func(wire []byte) error {
				_, err := ParseDTLSInitAck(wire)
				return err
			},
		},
		{
			name:         "CookieEcho",
			goldenHex:    dtlsCookieEchoGoldenHex,
			expectedSize: DTLSCookieEchoSize,
			expectedType: DTLSTypeCookieEcho,
			parse: func(wire []byte) error {
				_, err := ParseDTLSCookieEcho(wire)
				return err
			},
		},
		{
			name:         "CookieAck",
			goldenHex:    dtlsCookieAckGoldenHex,
			expectedSize: DTLSCookieAckSize,
			expectedType: DTLSTypeCookieAck,
			parse: func(wire []byte) error {
				_, err := ParseDTLSCookieAck(wire)
				return err
			},
		},
		{
			name:         "Error",
			goldenHex:    dtlsErrorGoldenHex,
			expectedSize: DTLSErrorSize,
			expectedType: DTLSTypeError,
			parse: func(wire []byte) error {
				_, err := ParseDTLSError(wire)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			golden := decodeDTLSGolden(t, test.goldenHex, test.expectedSize)
			mutations := map[string][]byte{
				"empty":      nil,
				"truncated":  append([]byte(nil), golden[:len(golden)-1]...),
				"trailing":   append(append([]byte(nil), golden...), 0),
				"wrong type": replaceDTLSByte(golden, 0, alternateDTLSType(test.expectedType)),
				"version 1":  replaceDTLSByte(golden, 1, 1),
				"version 3":  replaceDTLSByte(golden, 1, 3),
			}
			for name, wire := range mutations {
				t.Run(name, func(t *testing.T) {
					if err := test.parse(wire); err == nil {
						t.Fatalf("accepted malformed packet: %x", wire)
					}
				})
			}
		})
	}
}

func TestDTLSInitAckRejectsMismatchedDuplicateResponderTag(t *testing.T) {
	wire := decodeDTLSGolden(t, dtlsInitAckGoldenHex, DTLSInitAckSize)
	wire[16] ^= 1
	if packet, err := ParseDTLSInitAck(wire); err == nil {
		t.Fatalf("accepted mismatched duplicate responder tag: %#v", packet)
	}
}

func TestDTLSMarshalersRejectNoncanonicalHeaderRelations(t *testing.T) {
	validInit := DTLSInit{
		InitiatorLocalTag:  0x5566,
		SecurityIdentifier: dtlsBlob8(0),
	}
	validInitAck := dtlsInitAckFixture()
	validCookieEcho := DTLSCookieEcho{
		Header:        DTLSHeader{VerificationTag: validInitAck.ResponderTag},
		InitAck:       validInitAck,
		CommonAddress: dtlsCommonAddress(0x20),
		Blob:          dtlsBlob8(0x40),
		PublicKey:     dtlsPublicKey(0x80),
	}
	validCookieAck := DTLSCookieAck{
		Header:    DTLSHeader{VerificationTag: 0x3132},
		PublicKey: dtlsPublicKey(0x80),
		Blob:      dtlsBlob8(0xf0),
	}

	tests := []struct {
		name    string
		marshal func() ([]byte, error)
	}{
		{
			name: "Init nonzero verification tag",
			marshal: func() ([]byte, error) {
				packet := validInit
				packet.Header.VerificationTag = 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "Init nonzero sequence tag",
			marshal: func() ([]byte, error) {
				packet := validInit
				packet.Header.SequenceTag = 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "InitAck verification differs from initiator",
			marshal: func() ([]byte, error) {
				packet := validInitAck
				packet.Header.VerificationTag ^= 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "InitAck nonzero sequence tag",
			marshal: func() ([]byte, error) {
				packet := validInitAck
				packet.Header.SequenceTag = 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "CookieEcho verification differs from responder",
			marshal: func() ([]byte, error) {
				packet := validCookieEcho
				packet.Header.VerificationTag ^= 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "CookieEcho nonzero sequence tag",
			marshal: func() ([]byte, error) {
				packet := validCookieEcho
				packet.Header.SequenceTag = 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "CookieEcho contains noncanonical nested InitAck",
			marshal: func() ([]byte, error) {
				packet := validCookieEcho
				packet.InitAck.Header.VerificationTag ^= 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "CookieAck nonzero sequence tag",
			marshal: func() ([]byte, error) {
				packet := validCookieAck
				packet.Header.SequenceTag = 1
				return packet.MarshalBinary()
			},
		},
		{
			name: "Error nonzero sequence tag",
			marshal: func() ([]byte, error) {
				packet := DTLSError{
					Header:             DTLSHeader{VerificationTag: 0x1234, SequenceTag: 1},
					ErrorType:          DTLSErrorBadSecurityID,
					SecurityIdentifier: dtlsBlob8(0),
				}
				return packet.MarshalBinary()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if wire, err := test.marshal(); err == nil {
				t.Fatalf("marshaled noncanonical packet: %x", wire)
			}
		})
	}
}

func TestDTLSCookieEchoRejectsInvalidNestedInitAck(t *testing.T) {
	golden := decodeDTLSGolden(t, dtlsCookieEchoGoldenHex, DTLSCookieEchoSize)
	tests := map[string][]byte{
		"wrong nested type":    replaceDTLSByte(golden, 6, DTLSTypeInit),
		"wrong nested version": replaceDTLSByte(golden, 7, 1),
		"duplicate mismatch":   replaceDTLSByte(golden, 6+16, golden[6+16]^1),
	}
	for name, wire := range tests {
		t.Run(name, func(t *testing.T) {
			if packet, err := ParseDTLSCookieEcho(wire); err == nil {
				t.Fatalf("accepted invalid nested InitAck: %#v", packet)
			}
		})
	}
}

func dtlsInitAckFixture() DTLSInitAck {
	return DTLSInitAck{
		Header:          DTLSHeader{VerificationTag: 0xbbcc},
		Timestamp:       0x55667788,
		CookieSignature: DTLSCookieSignature{0xa0, 0xa1, 0xa2, 0xa3},
		ResponderTag:    0x99aa,
		InitiatorTag:    0xbbcc,
		TieTagA:         0xddee,
		TieTagB:         0x0f10,
		Address:         Address{IPv4: [4]byte{192, 0, 2, 9}, Port: 3074},
		Blob:            dtlsBlob8(0x10),
	}
}

func dtlsBlob8(start byte) DTLSBlob8 {
	var value DTLSBlob8
	fillDTLSSequence(value[:], start)
	return value
}

func dtlsCommonAddress(start byte) DTLSCommonAddress {
	var value DTLSCommonAddress
	fillDTLSSequence(value[:], start)
	return value
}

func dtlsPublicKey(start byte) DTLSECCPublicKey {
	var value DTLSECCPublicKey
	fillDTLSSequence(value[:], start)
	return value
}

func dtlsSessionKey() []byte {
	key := make([]byte, DTLSSessionKeySize)
	fillDTLSSequence(key, 0)
	return key
}

func fillDTLSSequence(destination []byte, start byte) {
	for index := range destination {
		destination[index] = byte(int(start) + index)
	}
}

func decodeDTLSGolden(t *testing.T, encoded string, expectedSize int) []byte {
	t.Helper()
	wire, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode literal golden: %v", err)
	}
	if len(wire) != expectedSize {
		t.Fatalf("literal golden is %d bytes, want %d", len(wire), expectedSize)
	}
	return wire
}

func replaceDTLSByte(wire []byte, offset int, value byte) []byte {
	replaced := append([]byte(nil), wire...)
	replaced[offset] = value
	return replaced
}

func alternateDTLSType(expected byte) byte {
	if expected == DTLSTypeInit {
		return DTLSTypeInitAck
	}
	return DTLSTypeInit
}

func ExampleDTLSInit_wireLayout() {
	packet := DTLSInit{
		InitiatorLocalTag:  0x5566,
		SecurityIdentifier: dtlsBlob8(0),
	}
	wire, _ := packet.MarshalBinary()
	fmt.Printf("%x\n", wire)
	// Output: 01020000000066550001020304050607
}
