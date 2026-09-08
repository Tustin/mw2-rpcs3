package lsp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

const (
	packetType         = 0x0e
	registerCommand    = 0x03
	serverListCommand  = 0x04
	minimumRequestSize = 2
)

type ServerEntry struct {
	ID   uint16
	Type uint32
}

type Server struct {
	addr       string
	entries    []ServerEntry
	message    string
	version    uint32
	maxServers uint32
	log        *slog.Logger
	recorder   *capture.Recorder
	packets    atomic.Uint64
}

func New(addr string, entries []ServerEntry, message string, version, maxServers uint32, log *slog.Logger, recorder *capture.Recorder) *Server {
	return &Server{
		addr:       addr,
		entries:    append([]ServerEntry(nil), entries...),
		message:    message,
		version:    version,
		maxServers: maxServers,
		log:        log,
		recorder:   recorder,
	}
}

func (s *Server) Packets() uint64 { return s.packets.Load() }

func (s *Server) Serve(ctx context.Context) error {
	conn, err := net.ListenPacket("udp4", s.addr)
	if err != nil {
		return fmt.Errorf("listen on LSP address %q: %w", s.addr, err)
	}
	return s.servePacketConn(ctx, conn)
}

func (s *Server) servePacketConn(ctx context.Context, conn net.PacketConn) error {
	defer conn.Close()

	stopped := make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stopped:
		}
	}()

	buffer := make([]byte, 64<<10)
	for {
		n, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read LSP packet: %w", err)
		}
		s.packets.Add(1)
		packet := append([]byte(nil), buffer[:n]...)
		if s.recorder != nil {
			_ = s.recorder.Record("lsp", "in", remote.String(), packet)
		}
		response, command, ok := s.handlePacket(packet)
		if !ok {
			continue
		}
		if s.recorder != nil {
			_ = s.recorder.Record("lsp", "out", remote.String(), response)
		}
		if _, err := conn.WriteTo(response, remote); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("write LSP command %d response: %w", command, err)
		}
	}
}

func (s *Server) handlePacket(packet []byte) ([]byte, byte, bool) {
	if len(packet) < minimumRequestSize || packet[0] != packetType {
		return nil, 0, false
	}
	command := packet[1]
	switch command {
	case registerCommand:
		s.log.Debug("LSP registration received")
		return nil, command, false
	case serverListCommand:
		return s.serverListResponse(), command, true
	default:
		s.log.Debug("unsupported LSP command", "command", command)
		return nil, command, false
	}
}

func (s *Server) serverListResponse() []byte {
	message := []byte(s.message)
	response := make([]byte, 2+4+len(s.entries)*6+len(message)+1+4+4)
	response[0] = packetType
	response[1] = serverListCommand
	offset := 2
	binary.BigEndian.PutUint32(response[offset:offset+4], uint32(len(s.entries)))
	offset += 4
	for _, entry := range s.entries {
		binary.BigEndian.PutUint16(response[offset:offset+2], entry.ID)
		offset += 2
		binary.BigEndian.PutUint32(response[offset:offset+4], entry.Type)
		offset += 4
	}
	copy(response[offset:], message)
	offset += len(message) + 1
	binary.BigEndian.PutUint32(response[offset:offset+4], s.version)
	offset += 4
	binary.BigEndian.PutUint32(response[offset:offset+4], s.maxServers)
	return response
}
