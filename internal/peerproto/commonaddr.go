package peerproto

import (
	"fmt"

	"github.com/cxmcc/tiger"
)

const (
	CommonAddrSize              = 25
	CommonAddrAddressSize       = 6
	CommonAddrLocalAddressCount = 3
	CommonAddrIdentifierSize    = 4
)

// NATType is the one-byte NAT classification serialized by bdCommonAddr.
type NATType byte

const (
	NATTypeOpen     NATType = 1
	NATTypeModerate NATType = 2
	NATTypeStrict   NATType = 3
)

var defaultCommonAddrAddress = Address{
	IPv4: [4]byte{0x00, 0xff, 0x00, 0xff},
}

// DefaultCommonAddrAddress returns the exact bdAddr sentinel used for an
// unused local-address slot and for an unavailable public address.
func DefaultCommonAddrAddress() Address {
	return defaultCommonAddrAddress
}

// CommonAddr is MW2's canonical 25-byte bdCommonAddr representation. Local
// retains all three fixed wire slots, including unused sentinel slots.
type CommonAddr struct {
	Local  [CommonAddrLocalAddressCount]Address
	Public Address
	NAT    NATType
}

// MarshalBinary returns the exact canonical 25-byte representation.
func (common CommonAddr) MarshalBinary() ([]byte, error) {
	if err := common.validateCanonical(); err != nil {
		return nil, err
	}

	wire := make([]byte, CommonAddrSize)
	offset := 0
	for _, address := range common.Local {
		putAddress(wire[offset:offset+CommonAddrAddressSize], address)
		offset += CommonAddrAddressSize
	}
	putAddress(wire[offset:offset+CommonAddrAddressSize], common.Public)
	wire[CommonAddrSize-1] = byte(common.NAT)
	return wire, nil
}

// ParseCommonAddr parses one complete canonical CommonAddr. It rejects
// truncation, trailing bytes, invalid NAT values, nonzero sentinel ports, and
// gaps between populated local-address slots.
func ParseCommonAddr(wire []byte) (CommonAddr, error) {
	if len(wire) != CommonAddrSize {
		return CommonAddr{}, fmt.Errorf(
			"invalid MW2 common-address size %d, want %d",
			len(wire),
			CommonAddrSize,
		)
	}

	var common CommonAddr
	offset := 0
	for index := range common.Local {
		common.Local[index] = parseAddress(wire[offset : offset+CommonAddrAddressSize])
		offset += CommonAddrAddressSize
	}
	common.Public = parseAddress(wire[offset : offset+CommonAddrAddressSize])
	common.NAT = NATType(wire[CommonAddrSize-1])
	if err := common.validateCanonical(); err != nil {
		return CommonAddr{}, err
	}
	return common, nil
}

// EffectiveAddress returns the six-byte address MW2 hashes to identify this
// CommonAddr: public when available, otherwise local slot zero, otherwise the
// default sentinel.
func (common CommonAddr) EffectiveAddress() (Address, error) {
	if err := common.validateCanonical(); err != nil {
		return Address{}, err
	}

	effective := defaultCommonAddrAddress
	if commonAddressValid(common.Local[0]) {
		effective = common.Local[0]
	}
	if commonAddressValid(common.Public) {
		effective = common.Public
	}
	return effective, nil
}

// TigerIdentifier returns the exact four identifier bytes placed on the NAT
// traversal wire. MW2 Tiger-192 hashes only EffectiveAddress's six serialized
// bytes and copies the first four digest bytes unchanged to the packet.
func (common CommonAddr) TigerIdentifier() ([CommonAddrIdentifierSize]byte, error) {
	var identifier [CommonAddrIdentifierSize]byte
	effective, err := common.EffectiveAddress()
	if err != nil {
		return identifier, err
	}

	var input [CommonAddrAddressSize]byte
	putAddress(input[:], effective)
	hash := tiger.New()
	_, _ = hash.Write(input[:])
	copy(identifier[:], hash.Sum(nil)[:CommonAddrIdentifierSize])
	return identifier, nil
}

func (common CommonAddr) validateCanonical() error {
	if common.NAT < NATTypeOpen || common.NAT > NATTypeStrict {
		return fmt.Errorf("invalid MW2 common-address NAT type %d", common.NAT)
	}

	unusedSeen := false
	for index, address := range common.Local {
		if commonAddressValid(address) {
			if unusedSeen {
				return fmt.Errorf("noncanonical MW2 common-address local slot %d follows an unused slot", index)
			}
			continue
		}
		if address != defaultCommonAddrAddress {
			return fmt.Errorf("noncanonical MW2 common-address sentinel in local slot %d", index)
		}
		unusedSeen = true
	}

	if !commonAddressValid(common.Public) && common.Public != defaultCommonAddrAddress {
		return fmt.Errorf("noncanonical MW2 common-address public sentinel")
	}
	return nil
}

func commonAddressValid(address Address) bool {
	return address.IPv4 != defaultCommonAddrAddress.IPv4
}
