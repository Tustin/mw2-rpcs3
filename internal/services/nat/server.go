package nat

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

const (
	ipDiscoveryRequestType  = 0x1e
	ipDiscoveryResponseType = 0x1f
	ipDiscoveryVersion      = uint16(2)
	ipDiscoveryRequestSize  = 3

	natDiscoveryRequestType  = 0x14
	natDiscoveryResponseType = 0x15
	natDiscoveryRequestSize  = 4

	natCommandPrimaryReply   = 0
	natCommandAlternateReply = 3
	natCommandSecondAddress  = 2

	natTraversalRequestType    = 0x0a
	natTraversalForwardType    = 0x0b
	natTraversalPacketSize     = 29
	natTraversalMinVersion     = uint16(2)
	natTraversalDestIPOffset   = 0x17
	natTraversalDestPortOffset = 0x1b

	defaultAlternateAddr = ":3075"
)

type replySource uint8

const (
	replyFromPrimary replySource = iota
	replyFromAlternate
)

type Server struct {
	primaryAddr    string
	alternateAddr  string
	advertisedIPv4 string
	relayEnabled   bool
	log            *slog.Logger
	recorder       *capture.Recorder
	packets        atomic.Uint64
}

func New(addr string, log *slog.Logger, recorder *capture.Recorder) *Server {
	return NewWithAddresses(addr, defaultAlternateAddr, "", false, log, recorder)
}

func NewWithAddresses(
	primaryAddr,
	alternateAddr,
	advertisedIPv4 string,
	relayEnabled bool,
	log *slog.Logger,
	recorder *capture.Recorder,
) *Server {
	return &Server{
		primaryAddr:    primaryAddr,
		alternateAddr:  alternateAddr,
		advertisedIPv4: advertisedIPv4,
		relayEnabled:   relayEnabled,
		log:            log,
		recorder:       recorder,
	}
}

func (s *Server) Packets() uint64 { return s.packets.Load() }

func (s *Server) Serve(ctx context.Context) error {
	primary, err := net.ListenPacket("udp4", s.primaryAddr)
	if err != nil {
		return fmt.Errorf("listen on primary NAT address %q: %w", s.primaryAddr, err)
	}
	alternate, err := net.ListenPacket("udp4", s.alternateAddr)
	if err != nil {
		_ = primary.Close()
		return fmt.Errorf("listen on alternate NAT address %q: %w", s.alternateAddr, err)
	}
	// The client compares the command-3 reply's source IP with the IPv4
	// advertised inside the 0x15 body. Derive from the alternate reply-source
	// socket, not the primary socket, when no canonical address is configured.
	advertisedIPv4, err := resolveAdvertisedIPv4(s.advertisedIPv4, alternate.LocalAddr())
	if err != nil {
		_ = primary.Close()
		_ = alternate.Close()
		return err
	}
	return s.servePacketConns(ctx, primary, alternate, advertisedIPv4)
}

func (s *Server) servePacketConns(ctx context.Context, primary, alternate net.PacketConn, advertisedIPv4 net.IP) error {
	defer primary.Close()
	defer alternate.Close()

	primaryAddr, ok := primary.LocalAddr().(*net.UDPAddr)
	if !ok || primaryAddr == nil || primaryAddr.Port < 1 || primaryAddr.Port > 0xffff {
		return fmt.Errorf("primary NAT listener has invalid local address %v", primary.LocalAddr())
	}
	alternateAddr, ok := alternate.LocalAddr().(*net.UDPAddr)
	if !ok || alternateAddr == nil || alternateAddr.Port < 1 || alternateAddr.Port > 0xffff {
		return fmt.Errorf("alternate NAT listener has invalid local address %v", alternate.LocalAddr())
	}
	if primaryAddr.Port == alternateAddr.Port {
		return fmt.Errorf("primary and alternate NAT listeners must use different UDP ports")
	}
	advertisedIPv4 = advertisedIPv4.To4()
	if !usableAdvertisedIPv4(advertisedIPv4) {
		return fmt.Errorf("advertised NAT address must be a usable IPv4 address")
	}

	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = primary.Close()
			_ = alternate.Close()
		case <-stopped:
		}
	}()

	buffer := make([]byte, 2048)
	for {
		n, remote, err := primary.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.packets.Add(1)
		_ = s.recorder.Record("nat", "in", remote.String(), buffer[:n])

		if response, reply := ipDiscoveryReply(buffer[:n], remote); reply {
			s.writeReply(primary, remote, response[:])
			continue
		}

		if s.relayEnabled {
			if response, destination, relay := natTraversalForward(buffer[:n]); relay {
				s.writeReply(primary, destination, response[:])
				continue
			}
		}

		response, source, reply := natDiscoveryReply(buffer[:n], remote, advertisedIPv4, primaryAddr.Port)
		if !reply {
			continue
		}
		writer := primary
		if source == replyFromAlternate {
			writer = alternate
		}
		s.writeReply(writer, remote, response[:])
	}
}

func (s *Server) writeReply(conn net.PacketConn, remote net.Addr, response []byte) {
	_ = s.recorder.Record("nat", "out", remote.String(), response)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.WriteTo(response, remote); err != nil {
		s.log.Warn("nat response failed", "remote", remote, "error", err)
	}
}

func ipDiscoveryReply(packet []byte, remote net.Addr) ([9]byte, bool) {
	var response [9]byte
	if len(packet) != ipDiscoveryRequestSize ||
		packet[0] != ipDiscoveryRequestType ||
		binary.LittleEndian.Uint16(packet[1:]) != ipDiscoveryVersion {
		return response, false
	}

	ipv4, port, ok := observedUDPAddress(remote)
	if !ok {
		return response, false
	}

	response[0] = ipDiscoveryResponseType
	binary.LittleEndian.PutUint16(response[1:3], ipDiscoveryVersion)
	copy(response[3:7], ipv4)
	binary.LittleEndian.PutUint16(response[7:9], uint16(port))
	return response, true
}

func natDiscoveryReply(packet []byte, remote net.Addr, advertisedIPv4 net.IP, advertisedPort int) ([15]byte, replySource, bool) {
	var response [15]byte
	if len(packet) != natDiscoveryRequestSize ||
		packet[0] != natDiscoveryRequestType ||
		binary.LittleEndian.Uint16(packet[1:3]) != ipDiscoveryVersion {
		return response, replyFromPrimary, false
	}

	var source replySource
	switch packet[3] {
	case natCommandPrimaryReply:
		source = replyFromPrimary
	case natCommandAlternateReply, natCommandSecondAddress:
		source = replyFromAlternate
	default:
		return response, replyFromPrimary, false
	}

	observedIPv4, observedPort, ok := observedUDPAddress(remote)
	if !ok {
		return response, replyFromPrimary, false
	}
	advertisedIPv4 = advertisedIPv4.To4()
	if !usableAdvertisedIPv4(advertisedIPv4) || advertisedPort < 1 || advertisedPort > 0xffff {
		return response, replyFromPrimary, false
	}

	response[0] = natDiscoveryResponseType
	binary.LittleEndian.PutUint16(response[1:3], ipDiscoveryVersion)
	copy(response[3:7], observedIPv4)
	binary.LittleEndian.PutUint16(response[7:9], uint16(observedPort))
	copy(response[9:13], advertisedIPv4)
	binary.LittleEndian.PutUint16(response[13:15], uint16(advertisedPort))
	return response, source, true
}

func natTraversalForward(packet []byte) ([natTraversalPacketSize]byte, *net.UDPAddr, bool) {
	var forwarded [natTraversalPacketSize]byte
	if len(packet) != natTraversalPacketSize ||
		packet[0] != natTraversalRequestType ||
		binary.LittleEndian.Uint16(packet[1:3]) < natTraversalMinVersion {
		return forwarded, nil, false
	}

	copy(forwarded[:], packet)
	forwarded[0] = natTraversalForwardType
	destination := &net.UDPAddr{
		IP: net.IPv4(
			packet[natTraversalDestIPOffset],
			packet[natTraversalDestIPOffset+1],
			packet[natTraversalDestIPOffset+2],
			packet[natTraversalDestIPOffset+3],
		),
		Port: int(binary.LittleEndian.Uint16(packet[natTraversalDestPortOffset:natTraversalPacketSize])),
	}
	return forwarded, destination, true
}

func observedUDPAddress(remote net.Addr) (net.IP, int, bool) {
	udpAddr, ok := remote.(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.Port < 0 || udpAddr.Port > 0xffff {
		return nil, 0, false
	}
	ipv4 := udpAddr.IP.To4()
	if ipv4 == nil {
		return nil, 0, false
	}
	return ipv4, udpAddr.Port, true
}

func resolveAdvertisedIPv4(configured string, primaryLocalAddr net.Addr) (net.IP, error) {
	if configured != "" {
		ipv4 := net.ParseIP(configured).To4()
		if !usableAdvertisedIPv4(ipv4) {
			return nil, fmt.Errorf("MW2_NAT_ADVERTISED_IP must be a usable IPv4 address")
		}
		return append(net.IP(nil), ipv4...), nil
	}

	if udpAddr, ok := primaryLocalAddr.(*net.UDPAddr); ok && udpAddr != nil {
		if ipv4 := udpAddr.IP.To4(); usableAdvertisedIPv4(ipv4) {
			return append(net.IP(nil), ipv4...), nil
		}
	}
	if ipv4 := routeLocalIPv4(); usableAdvertisedIPv4(ipv4) {
		return ipv4, nil
	}
	if ipv4 := interfaceLocalIPv4(); usableAdvertisedIPv4(ipv4) {
		return ipv4, nil
	}
	return nil, fmt.Errorf("cannot determine a reachable IPv4 address; set MW2_NAT_ADVERTISED_IP")
}

func routeLocalIPv4() net.IP {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(192, 0, 2, 1),
		Port: 9,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil
	}
	ipv4 := local.IP.To4()
	if !usableAdvertisedIPv4(ipv4) {
		return nil
	}
	return append(net.IP(nil), ipv4...)
}

func interfaceLocalIPv4() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var loopback net.IP
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			continue
		}
		ipv4 := ip.To4()
		if !usableAdvertisedIPv4(ipv4) {
			continue
		}
		candidate := append(net.IP(nil), ipv4...)
		if !ipv4.IsLoopback() {
			return candidate
		}
		if loopback == nil {
			loopback = candidate
		}
	}
	return loopback
}

func usableAdvertisedIPv4(ip net.IP) bool {
	ipv4 := ip.To4()
	return ipv4 != nil &&
		!ipv4.IsUnspecified() &&
		!ipv4.IsMulticast() &&
		!ipv4.Equal(net.IPv4bcast)
}
