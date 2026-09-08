package lsp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func TestServerListResponse(t *testing.T) {
	server := New(":2005", []ServerEntry{{ID: 0x417e, Type: 1}, {ID: 0x417f, Type: 2}}, "IW4 LSP", 361, 120, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)

	response, command, ok := server.handlePacket([]byte{packetType, serverListCommand})
	if !ok || command != serverListCommand {
		t.Fatalf("handlePacket = ok %v command %d", ok, command)
	}
	if response[0] != packetType || response[1] != serverListCommand {
		t.Fatalf("response header = %x", response[:2])
	}
	if got := binary.BigEndian.Uint32(response[2:6]); got != 2 {
		t.Fatalf("entry count = %d, want 2", got)
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 0x417e {
		t.Fatalf("first ID = %#x", got)
	}
	if got := binary.BigEndian.Uint32(response[8:12]); got != 1 {
		t.Fatalf("first type = %d", got)
	}
	if got := binary.BigEndian.Uint16(response[12:14]); got != 0x417f {
		t.Fatalf("second ID = %#x", got)
	}
	if got := binary.BigEndian.Uint32(response[14:18]); got != 2 {
		t.Fatalf("second type = %d", got)
	}
	if !bytes.Equal(response[18:26], []byte("IW4 LSP\x00")) {
		t.Fatalf("message = %q", response[18:26])
	}
	if got := binary.BigEndian.Uint32(response[26:30]); got != 361 {
		t.Fatalf("version = %d", got)
	}
	if got := binary.BigEndian.Uint32(response[30:34]); got != 120 {
		t.Fatalf("max servers = %d", got)
	}
}

func TestRegistrationDoesNotReceiveListResponse(t *testing.T) {
	server := New(":2005", nil, "", 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if response, command, ok := server.handlePacket([]byte{packetType, registerCommand}); ok || response != nil || command != registerCommand {
		t.Fatalf("registration response = %x command %d ok %v", response, command, ok)
	}
}

func TestServePacketConnRespondsToCommand4(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := New(":2005", []ServerEntry{{ID: 0x417e, Type: 0}}, "", 0, 120, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.servePacketConn(ctx, conn) }()

	client, err := net.DialUDP("udp4", nil, conn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(time.Second)); err != nil {
		cancel()
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{packetType, serverListCommand}); err != nil {
		cancel()
		t.Fatal(err)
	}
	buffer := make([]byte, 128)
	n, err := client.Read(buffer)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if n != 21 || buffer[1] != serverListCommand || binary.BigEndian.Uint32(buffer[2:6]) != 1 {
		cancel()
		t.Fatalf("unexpected response %x", buffer[:n])
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop")
	}
}
