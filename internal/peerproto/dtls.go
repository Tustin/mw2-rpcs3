package peerproto

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	DTLSTypeInit       byte = 1
	DTLSTypeInitAck    byte = 2
	DTLSTypeCookieEcho byte = 3
	DTLSTypeCookieAck  byte = 4
	DTLSTypeError      byte = 5
	DTLSTypeData       byte = 6

	DTLSVersion byte = 2

	DTLSHeaderSize     = 6
	DTLSInitSize       = 16
	DTLSInitAckSize    = 38
	DTLSCookieEchoSize = 177
	DTLSCookieAckSize  = 114
	DTLSErrorSize      = 15
	DTLSDataFixedSize  = 16

	DTLSBlobSize            = 8
	DTLSCookieSignatureSize = 4
	DTLSCommonAddressSize   = 25
	DTLSECCPublicKeySize    = 100
	DTLSDataMACSize         = 8
	DTLSSessionKeySize      = 24
	DTLSDataMaxTitleSize    = 0x4ef
	DTLSDataMaxWireSize     = 0x504
)

var (
	// ErrDTLSDataAuthentication reports a type-6 packet whose truncated
	// HMAC-SHA1 tag does not match.
	ErrDTLSDataAuthentication = errors.New("MW2 bdDTLS Data authentication failed")

	// ErrDTLSVerificationTag reports an authenticated type-6 packet addressed
	// to a different association.
	ErrDTLSVerificationTag = errors.New("MW2 bdDTLS verification tag mismatch")

	// ErrDTLSReplayDuplicate reports an already-seen sequence in the active
	// 32-packet replay window.
	ErrDTLSReplayDuplicate = errors.New("duplicate MW2 bdDTLS Data sequence")

	// ErrDTLSReplayTooOld reports a sequence at least 32 packets behind the
	// replay-window high-water mark.
	ErrDTLSReplayTooOld = errors.New("MW2 bdDTLS Data sequence is outside replay window")
)

// DTLSHeader contains the two little-endian tags after the fixed packet type
// and version. Their precise role depends on the handshake state.
type DTLSHeader struct {
	VerificationTag uint16
	SequenceTag     uint16
}

// DTLSBlob8 is an eight-byte raw field. Its interpretation depends on the
// handshake packet containing it.
type DTLSBlob8 [DTLSBlobSize]byte

// DTLSCookieSignature is the raw four-byte signature in an InitAck.
type DTLSCookieSignature [DTLSCookieSignatureSize]byte

// DTLSCommonAddress is the complete raw 25-byte common-address record embedded
// in a CookieEcho.
type DTLSCommonAddress [DTLSCommonAddressSize]byte

// DTLSECCPublicKey is the raw 100-byte ECC public key used by CookieEcho and
// CookieAck.
type DTLSECCPublicKey [DTLSECCPublicKeySize]byte

// DTLSInit is the exact old-bdDTLS Init handshake packet used by MW2.
type DTLSInit struct {
	Header             DTLSHeader
	InitiatorLocalTag  uint16
	SecurityIdentifier DTLSBlob8
}

// MarshalBinary serializes an exact 16-byte Init packet. It enforces the
// canonical state-machine values produced by MW2: both common-header tags are
// zero. This construction-time validation is intentionally stricter than the
// low-level retail packet parser.
func (packet DTLSInit) MarshalBinary() ([]byte, error) {
	if packet.Header.VerificationTag != 0 {
		return nil, fmt.Errorf(
			"noncanonical MW2 bdDTLS Init verification tag %#04x, want zero",
			packet.Header.VerificationTag,
		)
	}
	if err := validateZeroDTLSSequence(DTLSTypeInit, packet.Header); err != nil {
		return nil, err
	}

	wire := make([]byte, DTLSInitSize)
	putDTLSHeader(wire, DTLSTypeInit, packet.Header)
	binary.LittleEndian.PutUint16(wire[6:8], packet.InitiatorLocalTag)
	copy(wire[8:16], packet.SecurityIdentifier[:])
	return wire, nil
}

// ParseDTLSInit parses one complete Init packet.
func ParseDTLSInit(wire []byte) (DTLSInit, error) {
	header, err := parseDTLSHeader(wire, DTLSInitSize, DTLSTypeInit)
	if err != nil {
		return DTLSInit{}, err
	}

	packet := DTLSInit{
		Header:            header,
		InitiatorLocalTag: binary.LittleEndian.Uint16(wire[6:8]),
	}
	copy(packet.SecurityIdentifier[:], wire[8:16])
	return packet, nil
}

// DTLSInitAck is the exact old-bdDTLS InitAck handshake packet. MW2 writes the
// responder tag twice; only one value is exposed and parsing requires both
// wire copies to agree. That equality check is canonical validation and is
// intentionally stricter than the low-level retail parser.
type DTLSInitAck struct {
	Header          DTLSHeader
	Timestamp       uint32
	CookieSignature DTLSCookieSignature
	ResponderTag    uint16
	InitiatorTag    uint16
	TieTagA         uint16
	TieTagB         uint16
	Address         Address
	Blob            DTLSBlob8
}

// MarshalBinary serializes an exact 38-byte InitAck packet. Canonical MW2
// construction requires a zero sequence tag and a verification tag equal to
// InitiatorTag. This is intentionally stricter than the low-level retail
// parser, which only deserializes the fields.
func (packet DTLSInitAck) MarshalBinary() ([]byte, error) {
	if err := validateZeroDTLSSequence(DTLSTypeInitAck, packet.Header); err != nil {
		return nil, err
	}
	if packet.Header.VerificationTag != packet.InitiatorTag {
		return nil, fmt.Errorf(
			"noncanonical MW2 bdDTLS InitAck verification tag %#04x, want initiator tag %#04x",
			packet.Header.VerificationTag,
			packet.InitiatorTag,
		)
	}

	wire := make([]byte, DTLSInitAckSize)
	putDTLSHeader(wire, DTLSTypeInitAck, packet.Header)
	binary.LittleEndian.PutUint32(wire[6:10], packet.Timestamp)
	copy(wire[10:14], packet.CookieSignature[:])
	binary.LittleEndian.PutUint16(wire[14:16], packet.ResponderTag)
	binary.LittleEndian.PutUint16(wire[16:18], packet.ResponderTag)
	binary.LittleEndian.PutUint16(wire[18:20], packet.InitiatorTag)
	binary.LittleEndian.PutUint16(wire[20:22], packet.TieTagA)
	binary.LittleEndian.PutUint16(wire[22:24], packet.TieTagB)
	putAddress(wire[24:30], packet.Address)
	copy(wire[30:38], packet.Blob[:])
	return wire, nil
}

// ParseDTLSInitAck parses one complete InitAck packet.
func ParseDTLSInitAck(wire []byte) (DTLSInitAck, error) {
	header, err := parseDTLSHeader(wire, DTLSInitAckSize, DTLSTypeInitAck)
	if err != nil {
		return DTLSInitAck{}, err
	}

	responderTag := binary.LittleEndian.Uint16(wire[14:16])
	duplicateResponderTag := binary.LittleEndian.Uint16(wire[16:18])
	if duplicateResponderTag != responderTag {
		return DTLSInitAck{}, fmt.Errorf(
			"invalid MW2 bdDTLS InitAck duplicate responder tag %#04x, want %#04x",
			duplicateResponderTag,
			responderTag,
		)
	}

	packet := DTLSInitAck{
		Header:       header,
		Timestamp:    binary.LittleEndian.Uint32(wire[6:10]),
		ResponderTag: responderTag,
		InitiatorTag: binary.LittleEndian.Uint16(wire[18:20]),
		TieTagA:      binary.LittleEndian.Uint16(wire[20:22]),
		TieTagB:      binary.LittleEndian.Uint16(wire[22:24]),
		Address:      parseAddress(wire[24:30]),
	}
	copy(packet.CookieSignature[:], wire[10:14])
	copy(packet.Blob[:], wire[30:38])
	return packet, nil
}

// DTLSCookieEcho is the exact old-bdDTLS CookieEcho handshake packet. InitAck
// is a complete nested 38-byte packet, including its own type and version.
type DTLSCookieEcho struct {
	Header        DTLSHeader
	InitAck       DTLSInitAck
	CommonAddress DTLSCommonAddress
	Blob          DTLSBlob8
	PublicKey     DTLSECCPublicKey
}

// MarshalBinary serializes an exact 177-byte CookieEcho packet. Canonical MW2
// construction requires a zero sequence tag and an outer verification tag
// equal to the nested InitAck responder tag. This is intentionally stricter
// than the low-level retail parser.
func (packet DTLSCookieEcho) MarshalBinary() ([]byte, error) {
	if err := validateZeroDTLSSequence(DTLSTypeCookieEcho, packet.Header); err != nil {
		return nil, err
	}
	if packet.Header.VerificationTag != packet.InitAck.ResponderTag {
		return nil, fmt.Errorf(
			"noncanonical MW2 bdDTLS CookieEcho verification tag %#04x, want responder tag %#04x",
			packet.Header.VerificationTag,
			packet.InitAck.ResponderTag,
		)
	}

	initAck, err := packet.InitAck.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal nested MW2 bdDTLS InitAck: %w", err)
	}

	wire := make([]byte, DTLSCookieEchoSize)
	putDTLSHeader(wire, DTLSTypeCookieEcho, packet.Header)
	copy(wire[6:44], initAck)
	copy(wire[44:69], packet.CommonAddress[:])
	copy(wire[69:77], packet.Blob[:])
	copy(wire[77:177], packet.PublicKey[:])
	return wire, nil
}

// ParseDTLSCookieEcho parses one complete CookieEcho packet.
func ParseDTLSCookieEcho(wire []byte) (DTLSCookieEcho, error) {
	header, err := parseDTLSHeader(wire, DTLSCookieEchoSize, DTLSTypeCookieEcho)
	if err != nil {
		return DTLSCookieEcho{}, err
	}

	initAck, err := ParseDTLSInitAck(wire[6:44])
	if err != nil {
		return DTLSCookieEcho{}, fmt.Errorf("parse nested MW2 bdDTLS InitAck: %w", err)
	}

	packet := DTLSCookieEcho{
		Header:  header,
		InitAck: initAck,
	}
	copy(packet.CommonAddress[:], wire[44:69])
	copy(packet.Blob[:], wire[69:77])
	copy(packet.PublicKey[:], wire[77:177])
	return packet, nil
}

// DTLSCookieAck is the exact old-bdDTLS CookieAck handshake packet.
type DTLSCookieAck struct {
	Header    DTLSHeader
	PublicKey DTLSECCPublicKey
	Blob      DTLSBlob8
}

// MarshalBinary serializes an exact 114-byte CookieAck packet. It requires the
// canonical zero sequence tag. CookieAck's verification tag is checked against
// initiator state outside this packet, so this isolated codec cannot validate
// that relation. Sequence validation remains intentionally stricter than the
// low-level retail packet parser.
func (packet DTLSCookieAck) MarshalBinary() ([]byte, error) {
	if err := validateZeroDTLSSequence(DTLSTypeCookieAck, packet.Header); err != nil {
		return nil, err
	}

	wire := make([]byte, DTLSCookieAckSize)
	putDTLSHeader(wire, DTLSTypeCookieAck, packet.Header)
	copy(wire[6:106], packet.PublicKey[:])
	copy(wire[106:114], packet.Blob[:])
	return wire, nil
}

// ParseDTLSCookieAck parses one complete CookieAck packet.
func ParseDTLSCookieAck(wire []byte) (DTLSCookieAck, error) {
	header, err := parseDTLSHeader(wire, DTLSCookieAckSize, DTLSTypeCookieAck)
	if err != nil {
		return DTLSCookieAck{}, err
	}

	packet := DTLSCookieAck{Header: header}
	copy(packet.PublicKey[:], wire[6:106])
	copy(packet.Blob[:], wire[106:114])
	return packet, nil
}

// DTLSErrorType is the one-byte error reason in a type-5 packet.
type DTLSErrorType byte

const (
	// DTLSErrorBadSecurityID is the only error value on which MW2's association
	// handler acts: it closes the association.
	DTLSErrorBadSecurityID DTLSErrorType = 0
)

// DTLSError is the exact fixed-width old-bdDTLS type-5 packet.
type DTLSError struct {
	Header             DTLSHeader
	ErrorType          DTLSErrorType
	SecurityIdentifier DTLSBlob8
}

// MarshalBinary serializes an exact 15-byte Error packet. MW2's sender always
// writes a zero sequence tag.
func (packet DTLSError) MarshalBinary() ([]byte, error) {
	if err := validateZeroDTLSSequence(DTLSTypeError, packet.Header); err != nil {
		return nil, err
	}

	wire := make([]byte, DTLSErrorSize)
	putDTLSHeader(wire, DTLSTypeError, packet.Header)
	wire[6] = byte(packet.ErrorType)
	copy(wire[7:15], packet.SecurityIdentifier[:])
	return wire, nil
}

// ParseDTLSError parses one complete Error packet.
func ParseDTLSError(wire []byte) (DTLSError, error) {
	header, err := parseDTLSHeader(wire, DTLSErrorSize, DTLSTypeError)
	if err != nil {
		return DTLSError{}, err
	}

	packet := DTLSError{
		Header:    header,
		ErrorType: DTLSErrorType(wire[6]),
	}
	copy(packet.SecurityIdentifier[:], wire[7:15])
	return packet, nil
}

// DTLSData is an authenticated old-bdDTLS type-6 packet. TitlePacket contains
// the original title payload, including its leading little-endian encrypted
// prefix length.
type DTLSData struct {
	Header      DTLSHeader
	TitlePacket []byte
}

// MarshalAuthenticated serializes and authenticates a type-6 packet. The
// 24-byte session key is the Tiger-derived association secret. MW2 transforms
// the padded encrypted prefix by XORing it with the repeated eight-byte
// security identifier; the remaining title bytes stay clear.
func (packet DTLSData) MarshalAuthenticated(
	sessionKey []byte,
	securityIdentifier DTLSBlob8,
) ([]byte, error) {
	if err := validateDTLSSessionKey(sessionKey); err != nil {
		return nil, err
	}
	if len(packet.TitlePacket) < 2 {
		return nil, fmt.Errorf(
			"invalid MW2 bdDTLS title packet size %d, want at least 2",
			len(packet.TitlePacket),
		)
	}
	if len(packet.TitlePacket) > DTLSDataMaxTitleSize {
		return nil, fmt.Errorf(
			"invalid MW2 bdDTLS title packet size %d, maximum is %d",
			len(packet.TitlePacket),
			DTLSDataMaxTitleSize,
		)
	}

	encryptedLength := int(binary.LittleEndian.Uint16(packet.TitlePacket[:2]))
	titlePayloadSize := len(packet.TitlePacket) - 2
	if encryptedLength > titlePayloadSize {
		return nil, fmt.Errorf(
			"invalid MW2 bdDTLS encrypted prefix length %d, title payload is %d bytes",
			encryptedLength,
			titlePayloadSize,
		)
	}

	paddedLength := alignDTLSDataLength(encryptedLength)
	clearLength := titlePayloadSize - encryptedLength
	wireSize := DTLSDataFixedSize + paddedLength + clearLength
	if wireSize > DTLSDataMaxWireSize {
		return nil, fmt.Errorf(
			"invalid MW2 bdDTLS Data packet size %d, maximum is %d",
			wireSize,
			DTLSDataMaxWireSize,
		)
	}

	wire := make([]byte, wireSize)
	putDTLSHeader(wire, DTLSTypeData, packet.Header)
	binary.LittleEndian.PutUint16(wire[14:16], uint16(encryptedLength))

	transformed := wire[DTLSDataFixedSize : DTLSDataFixedSize+paddedLength]
	copy(transformed, packet.TitlePacket[2:2+encryptedLength])
	for index := encryptedLength; index < paddedLength; index++ {
		transformed[index] = 0x01
	}
	for index := range transformed {
		transformed[index] ^= securityIdentifier[index%DTLSBlobSize]
	}

	copy(
		wire[DTLSDataFixedSize+paddedLength:],
		packet.TitlePacket[2+encryptedLength:],
	)
	copy(wire[6:14], authenticateDTLSData(wire, sessionKey))
	return wire, nil
}

// ParseDTLSData authenticates and decodes one complete type-6 packet. The
// two-byte encrypted-prefix length at wire offsets 14..15 is intentionally
// excluded from MW2's HMAC scope; it is still checked for structural safety.
func ParseDTLSData(
	wire []byte,
	sessionKey []byte,
	securityIdentifier DTLSBlob8,
) (DTLSData, error) {
	if err := validateDTLSSessionKey(sessionKey); err != nil {
		return DTLSData{}, err
	}
	if len(wire) < DTLSDataFixedSize {
		return DTLSData{}, fmt.Errorf(
			"invalid MW2 bdDTLS Data packet size %d, want at least %d",
			len(wire),
			DTLSDataFixedSize,
		)
	}
	// Retail's low-level parser is capacity-driven and has no literal 0x504
	// ceiling. This allocation-based parser intentionally enforces the maximum
	// packet that MW2's canonical 0x4ef-byte sender can produce.
	if len(wire) > DTLSDataMaxWireSize {
		return DTLSData{}, fmt.Errorf(
			"invalid MW2 bdDTLS Data packet size %d, maximum canonical size is %d",
			len(wire),
			DTLSDataMaxWireSize,
		)
	}
	if wire[0] != DTLSTypeData {
		return DTLSData{}, fmt.Errorf(
			"invalid MW2 bdDTLS packet type %d, want %d",
			wire[0],
			DTLSTypeData,
		)
	}
	if wire[1] != DTLSVersion {
		return DTLSData{}, fmt.Errorf(
			"invalid MW2 bdDTLS version %d, want %d",
			wire[1],
			DTLSVersion,
		)
	}

	encryptedLength := int(binary.LittleEndian.Uint16(wire[14:16]))
	paddedLength := alignDTLSDataLength(encryptedLength)
	if paddedLength > len(wire)-DTLSDataFixedSize {
		return DTLSData{}, fmt.Errorf(
			"invalid MW2 bdDTLS encrypted prefix length %d for %d-byte packet",
			encryptedLength,
			len(wire),
		)
	}

	expectedMAC := authenticateDTLSData(wire, sessionKey)
	if !hmac.Equal(wire[6:14], expectedMAC) {
		return DTLSData{}, ErrDTLSDataAuthentication
	}

	clearLength := len(wire) - DTLSDataFixedSize - paddedLength
	titlePacket := make([]byte, 2+encryptedLength+clearLength)
	binary.LittleEndian.PutUint16(titlePacket[:2], uint16(encryptedLength))
	for index := 0; index < encryptedLength; index++ {
		titlePacket[2+index] = wire[DTLSDataFixedSize+index] ^
			securityIdentifier[index%DTLSBlobSize]
	}
	copy(
		titlePacket[2+encryptedLength:],
		wire[DTLSDataFixedSize+paddedLength:],
	)

	return DTLSData{
		Header: DTLSHeader{
			VerificationTag: binary.LittleEndian.Uint16(wire[2:4]),
			SequenceTag:     binary.LittleEndian.Uint16(wire[4:6]),
		},
		TitlePacket: titlePacket,
	}, nil
}

// DTLSReplayWindow is MW2's 32-packet receive replay window. Its zero value is
// ready for use.
type DTLSReplayWindow struct {
	initialized bool
	highest     int32
	bitmap      uint32
}

// CheckAndMark expands a truncated 16-bit sequence around the current
// high-water mark, then records it if it is new and within the replay window.
func (window *DTLSReplayWindow) CheckAndMark(sequenceTag uint16) (uint32, error) {
	if window == nil {
		return 0, errors.New("nil MW2 bdDTLS replay window")
	}
	if !window.initialized {
		sequence := int32(sequenceTag)
		window.initialized = true
		window.highest = sequence
		window.bitmap = 1
		return uint32(sequence), nil
	}

	sequence := expandDTLSSequence(sequenceTag, window.highest)
	if sequence > window.highest {
		delta := sequence - window.highest
		if delta >= 32 {
			window.bitmap = 1
		} else {
			window.bitmap = (window.bitmap << delta) | 1
		}
		window.highest = sequence
		return uint32(sequence), nil
	}

	age := window.highest - sequence
	if age >= 32 {
		return uint32(sequence), ErrDTLSReplayTooOld
	}
	mask := uint32(1) << age
	if window.bitmap&mask != 0 {
		return uint32(sequence), ErrDTLSReplayDuplicate
	}
	window.bitmap |= mask
	return uint32(sequence), nil
}

// ParseDTLSDataWithReplay follows MW2's receive ordering: authenticate and
// decode first, then check the association verification tag, then mutate the
// replay window. Failed authentication and wrong-association packets therefore
// cannot consume sequence numbers.
func ParseDTLSDataWithReplay(
	wire []byte,
	sessionKey []byte,
	securityIdentifier DTLSBlob8,
	expectedVerificationTag uint16,
	replayWindow *DTLSReplayWindow,
) (DTLSData, uint32, error) {
	packet, err := ParseDTLSData(wire, sessionKey, securityIdentifier)
	if err != nil {
		return DTLSData{}, 0, err
	}
	if packet.Header.VerificationTag != expectedVerificationTag {
		return DTLSData{}, 0, fmt.Errorf(
			"%w: got %#04x, want %#04x",
			ErrDTLSVerificationTag,
			packet.Header.VerificationTag,
			expectedVerificationTag,
		)
	}
	sequence, err := replayWindow.CheckAndMark(packet.Header.SequenceTag)
	if err != nil {
		return DTLSData{}, sequence, err
	}
	return packet, sequence, nil
}

func validateDTLSSessionKey(sessionKey []byte) error {
	if len(sessionKey) != DTLSSessionKeySize {
		return fmt.Errorf(
			"invalid MW2 bdDTLS session key size %d, want %d",
			len(sessionKey),
			DTLSSessionKeySize,
		)
	}
	return nil
}

func alignDTLSDataLength(length int) int {
	return (length + (DTLSBlobSize - 1)) &^ (DTLSBlobSize - 1)
}

func authenticateDTLSData(wire, sessionKey []byte) []byte {
	mac := hmac.New(sha1.New, sessionKey)
	_, _ = mac.Write(wire[:DTLSHeaderSize])
	_, _ = mac.Write(wire[DTLSDataFixedSize:])
	return mac.Sum(nil)[:DTLSDataMACSize]
}

func expandDTLSSequence(sequenceTag uint16, highest int32) int32 {
	const (
		modulus = int32(1 << 16)
		half    = modulus / 2
	)

	remainder := highest % modulus
	if remainder < 0 {
		return int32(sequenceTag)
	}

	truncated := int32(sequenceTag)
	adjustment := int32(0)
	if remainder < truncated && truncated-remainder > half {
		adjustment = -modulus
	} else if remainder > truncated && remainder-truncated > half {
		adjustment = modulus
	}
	return highest - remainder + truncated + adjustment
}

func putDTLSHeader(wire []byte, packetType byte, header DTLSHeader) {
	wire[0] = packetType
	wire[1] = DTLSVersion
	binary.LittleEndian.PutUint16(wire[2:4], header.VerificationTag)
	binary.LittleEndian.PutUint16(wire[4:6], header.SequenceTag)
}

func validateZeroDTLSSequence(packetType byte, header DTLSHeader) error {
	if header.SequenceTag != 0 {
		return fmt.Errorf(
			"noncanonical MW2 bdDTLS type %d sequence tag %#04x, want zero",
			packetType,
			header.SequenceTag,
		)
	}
	return nil
}

func parseDTLSHeader(wire []byte, packetSize int, packetType byte) (DTLSHeader, error) {
	if len(wire) != packetSize {
		return DTLSHeader{}, fmt.Errorf(
			"invalid MW2 bdDTLS type %d packet size %d, want %d",
			packetType,
			len(wire),
			packetSize,
		)
	}
	if wire[0] != packetType {
		return DTLSHeader{}, fmt.Errorf(
			"invalid MW2 bdDTLS packet type %d, want %d",
			wire[0],
			packetType,
		)
	}
	if wire[1] != DTLSVersion {
		return DTLSHeader{}, fmt.Errorf(
			"invalid MW2 bdDTLS version %d, want %d",
			wire[1],
			DTLSVersion,
		)
	}

	return DTLSHeader{
		VerificationTag: binary.LittleEndian.Uint16(wire[2:4]),
		SequenceTag:     binary.LittleEndian.Uint16(wire[4:6]),
	}, nil
}
