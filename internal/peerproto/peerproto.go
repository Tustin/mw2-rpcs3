// Package peerproto implements the MW2 PS3 packets exchanged directly between
// game peers while testing reachability. These packets are not Demonware LSG
// service messages and must not be routed through the central service codec.
package peerproto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	QoSRequestType byte = 0x28
	QoSReplyType   byte = 0x29

	QoSRequestSize      = 17
	QoSReplyHeaderSize  = 18
	QoSMaxPacketSize    = 0x508
	QoSReplyMaxDataSize = QoSMaxPacketSize - QoSReplyHeaderSize

	// The executable accepts exactly these four traversal type values. Their
	// higher-level state-machine names are intentionally not inferred here.
	NATTraversalType0A byte = 0x0a
	NATTraversalType0B byte = 0x0b
	NATTraversalType0C byte = 0x0c
	NATTraversalType0D byte = 0x0d

	NATTraversalProtocolVersion uint16 = 2
	NATTraversalPacketSize             = 29
	NATTraversalSecretSize             = 28
	NATTraversalHMACSize               = 10

	MatchmakingSecurityIDSize = 8
)

var errInvalidSecretSize = errors.New("MW2 NAT traversal secret must be 28 bytes")

// QoSRequest is MW2's fixed-size peer QoS probe request. All multi-byte fields
// are little endian on the wire.
type QoSRequest struct {
	Timestamp uint64
	ProbeID   uint32
	// SecurityID is the first four raw bytes of the eight-byte matchmaking
	// security/session ID, interpreted as a little-endian u32.
	SecurityID uint32
}

// ShrinkSecurityID reproduces MW2's bdQoSProbe::shrinkSecId behavior. The
// first four raw bytes of the eight-byte matchmaking ID become the request's
// little-endian SecurityID value.
func ShrinkSecurityID(securityID []byte) (uint32, error) {
	if len(securityID) != MatchmakingSecurityIDSize {
		return 0, fmt.Errorf(
			"MW2 matchmaking security ID is %d bytes, want %d",
			len(securityID),
			MatchmakingSecurityIDSize,
		)
	}
	return binary.LittleEndian.Uint32(securityID[:4]), nil
}

// MarshalBinary serializes a QoS request into its exact 17-byte wire form.
func (request QoSRequest) MarshalBinary() ([]byte, error) {
	packet := make([]byte, QoSRequestSize)
	packet[0] = QoSRequestType
	binary.LittleEndian.PutUint64(packet[1:9], request.Timestamp)
	binary.LittleEndian.PutUint32(packet[9:13], request.ProbeID)
	binary.LittleEndian.PutUint32(packet[13:17], request.SecurityID)
	return packet, nil
}

// ParseQoSRequest parses one complete QoS request. It rejects truncation,
// trailing bytes, and every packet type other than 0x28.
func ParseQoSRequest(packet []byte) (QoSRequest, error) {
	if len(packet) != QoSRequestSize {
		return QoSRequest{}, fmt.Errorf("invalid MW2 QoS request size %d, want %d", len(packet), QoSRequestSize)
	}
	if packet[0] != QoSRequestType {
		return QoSRequest{}, fmt.Errorf("invalid MW2 QoS request type %#02x", packet[0])
	}

	return QoSRequest{
		Timestamp:  binary.LittleEndian.Uint64(packet[1:9]),
		ProbeID:    binary.LittleEndian.Uint32(packet[9:13]),
		SecurityID: binary.LittleEndian.Uint32(packet[13:17]),
	}, nil
}

// QoSReply is MW2's peer QoS probe reply. Data may be empty. The parser
// requires the packet remainder to match Data's declared length exactly.
type QoSReply struct {
	ProbeID   uint32
	Timestamp uint64
	Enabled   bool
	Data      []byte
}

// MarshalBinary serializes a QoS reply into its 18-byte header followed by
// Data. It returns a fresh packet that does not alias Data.
func (reply QoSReply) MarshalBinary() ([]byte, error) {
	if len(reply.Data) > QoSReplyMaxDataSize {
		return nil, fmt.Errorf(
			"MW2 QoS reply data is %d bytes, maximum is %d",
			len(reply.Data),
			QoSReplyMaxDataSize,
		)
	}

	packet := make([]byte, QoSReplyHeaderSize+len(reply.Data))
	packet[0] = QoSReplyType
	binary.LittleEndian.PutUint32(packet[1:5], reply.ProbeID)
	binary.LittleEndian.PutUint64(packet[5:13], reply.Timestamp)
	if reply.Enabled {
		packet[13] = 1
	}
	binary.LittleEndian.PutUint32(packet[14:18], uint32(len(reply.Data)))
	copy(packet[QoSReplyHeaderSize:], reply.Data)
	return packet, nil
}

// ParseQoSReply parses one complete QoS reply.
func ParseQoSReply(packet []byte) (QoSReply, error) {
	if len(packet) < QoSReplyHeaderSize {
		return QoSReply{}, fmt.Errorf("invalid MW2 QoS reply size %d, want at least %d", len(packet), QoSReplyHeaderSize)
	}
	if packet[0] != QoSReplyType {
		return QoSReply{}, fmt.Errorf("invalid MW2 QoS reply type %#02x", packet[0])
	}
	if packet[13] > 1 {
		return QoSReply{}, fmt.Errorf("invalid MW2 QoS reply enabled value %d", packet[13])
	}

	dataSize := binary.LittleEndian.Uint32(packet[14:18])
	remaining := len(packet) - QoSReplyHeaderSize
	if uint64(dataSize) != uint64(remaining) {
		return QoSReply{}, fmt.Errorf("invalid MW2 QoS reply data size %d with %d bytes remaining", dataSize, remaining)
	}
	if remaining > QoSReplyMaxDataSize {
		return QoSReply{}, fmt.Errorf(
			"MW2 QoS reply data is %d bytes, maximum is %d",
			remaining,
			QoSReplyMaxDataSize,
		)
	}

	data := make([]byte, remaining)
	copy(data, packet[QoSReplyHeaderSize:])
	return QoSReply{
		ProbeID:   binary.LittleEndian.Uint32(packet[1:5]),
		Timestamp: binary.LittleEndian.Uint64(packet[5:13]),
		Enabled:   packet[13] == 1,
		Data:      data,
	}, nil
}

// Address is the IPv4-plus-port form embedded in an MW2 NAT traversal packet.
// IPv4 octets remain in network order; Port is encoded little endian.
type Address struct {
	IPv4 [4]byte
	Port uint16
}

// NATTraversalPacket is the exact 29-byte peer NAT traversal envelope.
type NATTraversalPacket struct {
	Type            byte
	ProtocolVersion uint16
	HMAC            [NATTraversalHMACSize]byte
	Identifier      uint32
	Source          Address
	Destination     Address
}

// MarshalBinary serializes one complete NAT traversal packet.
func (packet NATTraversalPacket) MarshalBinary() ([]byte, error) {
	if !validNATTraversalType(packet.Type) {
		return nil, fmt.Errorf("invalid MW2 NAT traversal type %#02x", packet.Type)
	}
	if packet.ProtocolVersion < NATTraversalProtocolVersion {
		return nil, fmt.Errorf("unsupported MW2 NAT traversal protocol version %d", packet.ProtocolVersion)
	}

	wire := make([]byte, NATTraversalPacketSize)
	wire[0] = packet.Type
	binary.LittleEndian.PutUint16(wire[1:3], packet.ProtocolVersion)
	copy(wire[3:13], packet.HMAC[:])
	binary.LittleEndian.PutUint32(wire[13:17], packet.Identifier)
	putAddress(wire[17:23], packet.Source)
	putAddress(wire[23:29], packet.Destination)
	return wire, nil
}

// ParseNATTraversalPacket parses one complete NAT traversal packet. Version 2
// and later are accepted, matching the recovered MW2 parser.
func ParseNATTraversalPacket(wire []byte) (NATTraversalPacket, error) {
	if len(wire) != NATTraversalPacketSize {
		return NATTraversalPacket{}, fmt.Errorf("invalid MW2 NAT traversal packet size %d, want %d", len(wire), NATTraversalPacketSize)
	}
	if !validNATTraversalType(wire[0]) {
		return NATTraversalPacket{}, fmt.Errorf("invalid MW2 NAT traversal type %#02x", wire[0])
	}

	version := binary.LittleEndian.Uint16(wire[1:3])
	if version < NATTraversalProtocolVersion {
		return NATTraversalPacket{}, fmt.Errorf("unsupported MW2 NAT traversal protocol version %d", version)
	}

	packet := NATTraversalPacket{
		Type:            wire[0],
		ProtocolVersion: version,
		Identifier:      binary.LittleEndian.Uint32(wire[13:17]),
		Source:          parseAddress(wire[17:23]),
		Destination:     parseAddress(wire[23:29]),
	}
	copy(packet.HMAC[:], wire[3:13])
	return packet, nil
}

// CalculateNATTraversalHMAC calculates MW2's ten-byte truncated HMAC-SHA1.
// The authenticated message is the little-endian identifier followed by the
// six-byte source and destination wire addresses. Type, version, and the HMAC
// field itself are not authenticated.
func CalculateNATTraversalHMAC(secret []byte, identifier uint32, source, destination Address) ([NATTraversalHMACSize]byte, error) {
	var result [NATTraversalHMACSize]byte
	if len(secret) != NATTraversalSecretSize {
		return result, errInvalidSecretSize
	}

	authenticated := make([]byte, 16)
	binary.LittleEndian.PutUint32(authenticated[0:4], identifier)
	putAddress(authenticated[4:10], source)
	putAddress(authenticated[10:16], destination)

	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(authenticated)
	copy(result[:], mac.Sum(nil)[:NATTraversalHMACSize])
	return result, nil
}

// VerifyNATTraversalHMAC compares a packet's HMAC in constant time.
func VerifyNATTraversalHMAC(secret []byte, packet NATTraversalPacket) (bool, error) {
	expected, err := CalculateNATTraversalHMAC(secret, packet.Identifier, packet.Source, packet.Destination)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(packet.HMAC[:], expected[:]) == 1, nil
}

func validNATTraversalType(packetType byte) bool {
	return packetType >= NATTraversalType0A && packetType <= NATTraversalType0D
}

func putAddress(wire []byte, address Address) {
	copy(wire[0:4], address.IPv4[:])
	binary.LittleEndian.PutUint16(wire[4:6], address.Port)
}

func parseAddress(wire []byte) Address {
	var address Address
	copy(address.IPv4[:], wire[0:4])
	address.Port = binary.LittleEndian.Uint16(wire[4:6])
	return address
}
