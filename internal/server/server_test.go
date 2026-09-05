package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
	"github.com/josh/mw2-rpcs3/internal/protocol"
)

func TestTCPServerCancellationClosesConnectedClients(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	service := NewTCP(
		"test",
		address,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		protocol.NewDispatcher(),
		capture.New(false, "", 16<<20),
		16<<20,
		5*time.Minute,
		5*time.Second,
	)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- service.Serve(ctx)
	}()

	var conn net.Conn
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		conn, err = net.DialTimeout("tcp", address, 50*time.Millisecond)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("dial server: %v", err)
	}
	defer conn.Close()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("server stopped with error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not stop with a connected client")
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var value [1]byte
	if _, err := conn.Read(value[:]); err == nil {
		t.Fatal("connected client remained open after cancellation")
	}
}
