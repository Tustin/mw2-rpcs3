package nat

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

func TestIPDiscoveryReplyV2Golden(t *testing.T) {
	remote := &net.UDPAddr{
		IP:   net.ParseIP("203.0.113.9"),
		Port: 0x1234,
	}

	got, ok := ipDiscoveryReply([]byte{0x1e, 0x02, 0x00}, remote)
	if !ok {
		t.Fatal("valid v2 discovery request was rejected")
	}

	want := [9]byte{
		0x1f, 0x02, 0x00,
		0xcb, 0x00, 0x71, 0x09,
		0x34, 0x12,
	}
	if got != want {
		t.Fatalf("reply = % x, want % x", got, want)
	}
}

func TestIPDiscoveryReplyMatchesCapturedMW2Response(t *testing.T) {
	remote := &net.UDPAddr{
		IP:   net.IPv4(0x18, 0xd8, 0xa2, 0x6f),
		Port: 3074,
	}

	got, ok := ipDiscoveryReply([]byte{0x1e, 0x02, 0x00}, remote)
	if !ok {
		t.Fatal("recovered MW2 discovery request was rejected")
	}

	want := [9]byte{0x1f, 0x02, 0x00, 0x18, 0xd8, 0xa2, 0x6f, 0x02, 0x0c}
	if got != want {
		t.Fatalf("reply = % x, want captured % x", got, want)
	}
}

func TestIPDiscoveryReplyRejectsMalformedOrUnsupportedPackets(t *testing.T) {
	validRemote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 3074}
	alternateAddressReply := make([]byte, 15)
	alternateAddressReply[0] = 0x15
	tests := []struct {
		name   string
		packet []byte
		remote net.Addr
	}{
		{name: "empty", remote: validRemote},
		{name: "truncated version", packet: []byte{0x1e, 0x02}, remote: validRemote},
		{name: "wrong type", packet: []byte{0x1f, 0x02, 0x00}, remote: validRemote},
		{name: "alternate address type 0x14", packet: []byte{0x14, 0x02, 0x00}, remote: validRemote},
		{name: "15-byte type 0x15", packet: alternateAddressReply, remote: validRemote},
		{name: "version one", packet: []byte{0x1e, 0x01, 0x00}, remote: validRemote},
		{name: "version two big endian", packet: []byte{0x1e, 0x00, 0x02}, remote: validRemote},
		{name: "trailing byte", packet: []byte{0x1e, 0x02, 0x00, 0x00}, remote: validRemote},
		{name: "missing source", packet: []byte{0x1e, 0x02, 0x00}},
		{name: "typed nil source", packet: []byte{0x1e, 0x02, 0x00}, remote: (*net.UDPAddr)(nil)},
		{name: "ipv6 source", packet: []byte{0x1e, 0x02, 0x00}, remote: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3074}},
		{name: "non udp source", packet: []byte{0x1e, 0x02, 0x00}, remote: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 3074}},
		{name: "negative port", packet: []byte{0x1e, 0x02, 0x00}, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: -1}},
		{name: "oversized port", packet: []byte{0x1e, 0x02, 0x00}, remote: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 1 << 16}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if reply, ok := ipDiscoveryReply(test.packet, test.remote); ok {
				t.Fatalf("unexpected reply: % x", reply)
			}
		})
	}
}

func TestNATTraversalForwardV2Golden(t *testing.T) {
	packet := []byte{
		0x0a, 0x02, 0x00,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x78, 0x56, 0x34, 0x12,
		0xcb, 0x00, 0x71, 0x09, 0x6e, 0xb2,
		0xc6, 0x33, 0x64, 0x4d, 0x34, 0x12,
	}

	got, destination, ok := natTraversalForward(packet)
	if !ok {
		t.Fatal("valid v2 NAT traversal request was rejected")
	}
	if destination == nil {
		t.Fatal("valid v2 NAT traversal request has no destination")
	}
	if !destination.IP.Equal(net.IPv4(198, 51, 100, 77)) || destination.Port != 0x1234 {
		t.Fatalf("destination = %s, want 198.51.100.77:4660", destination)
	}

	want := append([]byte(nil), packet...)
	want[0] = 0x0b
	if !bytes.Equal(got[:], want) {
		t.Fatalf("forwarded packet = % x, want % x", got, want)
	}
}

func TestNATTraversalForwardAcceptsVersionsAtLeastTwo(t *testing.T) {
	destination := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 3074}
	for _, version := range []uint16{2, 3, 0xffff} {
		t.Run(fmt.Sprintf("version_%d", version), func(t *testing.T) {
			packet := testNATTraversalRequest(destination, version)
			if _, _, ok := natTraversalForward(packet); !ok {
				t.Fatalf("version %d was rejected", version)
			}
		})
	}
}

func TestNATTraversalForwardRejectsMalformedOrUnsupportedPackets(t *testing.T) {
	valid := testNATTraversalRequest(
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 3074},
		2,
	)
	tests := []struct {
		name   string
		packet []byte
	}{
		{name: "empty"},
		{name: "short", packet: append([]byte(nil), valid[:natTraversalPacketSize-1]...)},
		{name: "long", packet: append(append([]byte(nil), valid...), 0x00)},
		{name: "forward type", packet: mutateByte(valid, 0, natTraversalForwardType)},
		{name: "direct request type", packet: mutateByte(valid, 0, 0x0d)},
		{name: "version zero", packet: mutateVersion(valid, 0)},
		{name: "version one", packet: mutateVersion(valid, 1)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if forwarded, destination, ok := natTraversalForward(test.packet); ok {
				t.Fatalf("unexpected forward to %v: % x", destination, forwarded)
			}
		})
	}
}

func TestNATDiscoveryReplyV2PCAPGolden(t *testing.T) {
	remote := &net.UDPAddr{
		IP:   net.IPv4(0x18, 0xd8, 0xa2, 0x6f),
		Port: 3074,
	}
	advertisedIPv4 := net.IPv4(0xb9, 0x22, 0x6b, 0x81)

	got, source, ok := natDiscoveryReply(
		[]byte{0x14, 0x02, 0x00, 0x00},
		remote,
		advertisedIPv4,
		3074,
	)
	if !ok {
		t.Fatal("recovered MW2 NAT discovery request was rejected")
	}
	if source != replyFromPrimary {
		t.Fatalf("source = %d, want primary", source)
	}

	want := [15]byte{
		0x15, 0x02, 0x00,
		0x18, 0xd8, 0xa2, 0x6f,
		0x02, 0x0c,
		0xb9, 0x22, 0x6b, 0x81,
		0x02, 0x0c,
	}
	if got != want {
		t.Fatalf("reply = % x, want captured % x", got, want)
	}
}

func TestNATDiscoveryCommandsSelectReplySocket(t *testing.T) {
	remote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 0x1234}
	advertisedIPv4 := net.IPv4(198, 51, 100, 20)
	tests := []struct {
		command byte
		source  replySource
	}{
		{command: 0, source: replyFromPrimary},
		{command: 3, source: replyFromAlternate},
		{command: 2, source: replyFromAlternate},
	}

	for _, test := range tests {
		t.Run(string(rune('0'+test.command)), func(t *testing.T) {
			got, source, ok := natDiscoveryReply(
				[]byte{0x14, 0x02, 0x00, test.command},
				remote,
				advertisedIPv4,
				3074,
			)
			if !ok {
				t.Fatalf("command %d was rejected", test.command)
			}
			if source != test.source {
				t.Fatalf("source = %d, want %d", source, test.source)
			}
			want := [15]byte{
				0x15, 0x02, 0x00,
				0xc0, 0x00, 0x02, 0x0a,
				0x34, 0x12,
				0xc6, 0x33, 0x64, 0x14,
				0x02, 0x0c,
			}
			if got != want {
				t.Fatalf("reply = % x, want % x", got, want)
			}
		})
	}
}

func TestNATDiscoveryReplyRejectsMalformedOrUnsupportedPackets(t *testing.T) {
	validRemote := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 3074}
	validAdvertisedIPv4 := net.IPv4(198, 51, 100, 20)
	tests := []struct {
		name           string
		packet         []byte
		remote         net.Addr
		advertisedIPv4 net.IP
		advertisedPort int
	}{
		{name: "empty", remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "truncated", packet: []byte{0x14, 0x02, 0x00}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "trailing byte", packet: []byte{0x14, 0x02, 0x00, 0x00, 0x00}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "wrong type", packet: []byte{0x15, 0x02, 0x00, 0x00}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "version one", packet: []byte{0x14, 0x01, 0x00, 0x00}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "version two big endian", packet: []byte{0x14, 0x00, 0x02, 0x00}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "command one", packet: []byte{0x14, 0x02, 0x00, 0x01}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "command four", packet: []byte{0x14, 0x02, 0x00, 0x04}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "ipv6 source", packet: []byte{0x14, 0x02, 0x00, 0x00}, remote: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 3074}, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 3074},
		{name: "missing advertised IP", packet: []byte{0x14, 0x02, 0x00, 0x00}, remote: validRemote, advertisedPort: 3074},
		{name: "unspecified advertised IP", packet: []byte{0x14, 0x02, 0x00, 0x00}, remote: validRemote, advertisedIPv4: net.IPv4zero, advertisedPort: 3074},
		{name: "zero advertised port", packet: []byte{0x14, 0x02, 0x00, 0x00}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4},
		{name: "oversized advertised port", packet: []byte{0x14, 0x02, 0x00, 0x00}, remote: validRemote, advertisedIPv4: validAdvertisedIPv4, advertisedPort: 1 << 16},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if reply, _, ok := natDiscoveryReply(
				test.packet,
				test.remote,
				test.advertisedIPv4,
				test.advertisedPort,
			); ok {
				t.Fatalf("unexpected reply: % x", reply)
			}
		})
	}
}

func TestServePacketConnsUsesRequiredReplySocketAndCancels(t *testing.T) {
	primary := listenTestUDP(t)
	alternate := listenTestUDP(t)
	primaryAddr := primary.LocalAddr().(*net.UDPAddr)
	alternateAddr := alternate.LocalAddr().(*net.UDPAddr)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewWithAddresses("", "", "", false, log, capture.New(false, "", 2048))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.servePacketConns(ctx, primary, alternate, net.IPv4(127, 0, 0, 1))
	}()

	client := listenTestUDP(t)
	defer client.Close()
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	tests := []struct {
		name       string
		request    []byte
		replySize  int
		sourcePort int
	}{
		{name: "IP discovery", request: []byte{0x1e, 0x02, 0x00}, replySize: 9, sourcePort: primaryAddr.Port},
		{name: "NAT command 0", request: []byte{0x14, 0x02, 0x00, 0x00}, replySize: 15, sourcePort: primaryAddr.Port},
		{name: "NAT command 3", request: []byte{0x14, 0x02, 0x00, 0x03}, replySize: 15, sourcePort: alternateAddr.Port},
		{name: "NAT command 2", request: []byte{0x14, 0x02, 0x00, 0x02}, replySize: 15, sourcePort: alternateAddr.Port},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.WriteTo(test.request, primaryAddr); err != nil {
				t.Fatal(err)
			}
			if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			n, source, err := client.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if n != test.replySize {
				t.Fatalf("reply length = %d, want %d", n, test.replySize)
			}
			sourceAddr, ok := source.(*net.UDPAddr)
			if !ok {
				t.Fatalf("source = %T, want *net.UDPAddr", source)
			}
			if sourceAddr.Port != test.sourcePort {
				t.Fatalf("source port = %d, want %d", sourceAddr.Port, test.sourcePort)
			}
			if !sourceAddr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
				t.Fatalf("source IP = %s, want 127.0.0.1", sourceAddr.IP)
			}

			if !net.IP(buffer[3:7]).Equal(clientAddr.IP) {
				t.Fatalf("observed IP = %v, want %s", buffer[3:7], clientAddr.IP)
			}
			if got := binary.LittleEndian.Uint16(buffer[7:9]); got != uint16(clientAddr.Port) {
				t.Fatalf("observed port = %d, want %d", got, clientAddr.Port)
			}
			if test.replySize == 15 {
				if !net.IP(buffer[9:13]).Equal(net.IPv4(127, 0, 0, 1)) {
					t.Fatalf("advertised IP = %v, want 127.0.0.1", buffer[9:13])
				}
				if got := binary.LittleEndian.Uint16(buffer[13:15]); got != uint16(primaryAddr.Port) {
					t.Fatalf("advertised port = %d, want %d", got, primaryAddr.Port)
				}
			}
		})
	}

	if got := server.Packets(); got != uint64(len(tests)) {
		t.Fatalf("packets = %d, want %d", got, len(tests))
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}

func TestServePacketConnsForwardsNATTraversalFromPrimaryListener(t *testing.T) {
	primary := listenTestUDP(t)
	alternate := listenTestUDP(t)
	primaryAddr := primary.LocalAddr().(*net.UDPAddr)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewWithAddresses("", "", "", true, log, capture.New(false, "", 2048))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- server.servePacketConns(ctx, primary, alternate, net.IPv4(127, 0, 0, 1))
	}()

	receiver := listenTestUDP(t)
	defer receiver.Close()
	client := listenTestUDP(t)
	defer client.Close()

	request := testNATTraversalRequest(receiver.LocalAddr().(*net.UDPAddr), 2)
	if _, err := client.WriteTo(request, primaryAddr); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, source, err := receiver.ReadFrom(buffer)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte(nil), request...)
	want[0] = natTraversalForwardType
	if !bytes.Equal(buffer[:n], want) {
		t.Fatalf("forwarded packet = % x, want % x", buffer[:n], want)
	}

	sourceAddr, ok := source.(*net.UDPAddr)
	if !ok {
		t.Fatalf("source = %T, want *net.UDPAddr", source)
	}
	if sourceAddr.Port != primaryAddr.Port {
		t.Fatalf("source port = %d, want primary listener port %d", sourceAddr.Port, primaryAddr.Port)
	}
	if !sourceAddr.IP.Equal(primaryAddr.IP) {
		t.Fatalf("source IP = %s, want primary listener IP %s", sourceAddr.IP, primaryAddr.IP)
	}
	if got := server.Packets(); got != 1 {
		t.Fatalf("packets = %d, want 1", got)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}

func TestServePacketConnsDoesNotRelayWhenDisabled(t *testing.T) {
	primary := listenTestUDP(t)
	alternate := listenTestUDP(t)
	primaryAddr := primary.LocalAddr().(*net.UDPAddr)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewWithAddresses("", "", "", false, log, capture.New(false, "", 2048))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.servePacketConns(ctx, primary, alternate, net.IPv4(127, 0, 0, 1))
	}()

	receiver := listenTestUDP(t)
	defer receiver.Close()
	client := listenTestUDP(t)
	defer client.Close()

	request := testNATTraversalRequest(receiver.LocalAddr().(*net.UDPAddr), 2)
	if _, err := client.WriteTo(request, primaryAddr); err != nil {
		t.Fatal(err)
	}
	if err := receiver.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	if _, _, err := receiver.ReadFrom(buffer); err == nil {
		t.Fatal("disabled introducer relay forwarded a packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("disabled relay read error = %v, want timeout", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after cancellation")
	}
}

func TestServeReportsAlternateBindFailure(t *testing.T) {
	occupied := listenTestUDP(t)
	defer occupied.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := NewWithAddresses(
		"127.0.0.1:0",
		occupied.LocalAddr().String(),
		"127.0.0.1",
		false,
		log,
		capture.New(false, "", 2048),
	)
	err := server.Serve(context.Background())
	if err == nil {
		t.Fatal("expected alternate listener bind error")
	}
	if !strings.Contains(err.Error(), "alternate NAT address") {
		t.Fatalf("error = %q, want alternate-listener context", err)
	}
}

func TestResolveAdvertisedIPv4PrefersConfiguredThenAlternateSourceBind(t *testing.T) {
	got, err := ResolveAdvertisedIPv4(
		"198.51.100.22",
		&net.UDPAddr{IP: net.IPv4zero, Port: 3075},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(net.IPv4(198, 51, 100, 22)) {
		t.Fatalf("configured result = %s", got)
	}

	got, err = ResolveAdvertisedIPv4(
		"",
		&net.UDPAddr{IP: net.IPv4(192, 0, 2, 44), Port: 3075},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(net.IPv4(192, 0, 2, 44)) {
		t.Fatalf("specific-bind result = %s", got)
	}

	if _, err := ResolveAdvertisedIPv4(
		"2001:db8::1",
		&net.UDPAddr{IP: net.IPv4zero, Port: 3075},
	); err == nil {
		t.Fatal("accepted IPv6 advertised address")
	}
}

func listenTestUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func testNATTraversalRequest(destination *net.UDPAddr, version uint16) []byte {
	packet := []byte{
		natTraversalRequestType, 0x00, 0x00,
		0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		0xf0, 0xde, 0xbc, 0x9a,
		0xcb, 0x00, 0x71, 0x09, 0x6e, 0xb2,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	binary.LittleEndian.PutUint16(packet[1:3], version)
	copy(packet[natTraversalDestIPOffset:natTraversalDestPortOffset], destination.IP.To4())
	binary.LittleEndian.PutUint16(packet[natTraversalDestPortOffset:natTraversalPacketSize], uint16(destination.Port))
	return packet
}

func TestBandwidthUploadSequence(t *testing.T) {
	packet := make([]byte, bandwidthUploadPacketSize)
	binary.LittleEndian.PutUint32(packet[:4], 3)
	copy(packet[4:12], []byte{0, 1, 2, 3, 4, 5, 6, 7})

	sequence, ok := bandwidthUploadSequence(packet)
	if !ok || sequence != 3 {
		t.Fatalf("sequence=%d ok=%v", sequence, ok)
	}

	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "short", mutate: func(value []byte) []byte { return value[:len(value)-1] }},
		{name: "sequence out of range", mutate: func(value []byte) []byte {
			binary.LittleEndian.PutUint32(value[:4], bandwidthUploadPackets)
			return value
		}},
		{name: "wrong token", mutate: func(value []byte) []byte {
			value[11] ^= 0xff
			return value
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := append([]byte(nil), packet...)
			if _, ok := bandwidthUploadSequence(test.mutate(candidate)); ok {
				t.Fatal("accepted malformed bandwidth upload")
			}
		})
	}
}

func mutateByte(packet []byte, offset int, value byte) []byte {
	mutated := append([]byte(nil), packet...)
	mutated[offset] = value
	return mutated
}

func mutateVersion(packet []byte, version uint16) []byte {
	mutated := append([]byte(nil), packet...)
	binary.LittleEndian.PutUint16(mutated[1:3], version)
	return mutated
}
