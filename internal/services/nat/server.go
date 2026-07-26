package nat

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
)

type Server struct {
	addr     string
	log      *slog.Logger
	recorder *capture.Recorder
	packets  atomic.Uint64
}

func New(addr string, log *slog.Logger, recorder *capture.Recorder) *Server {
	return &Server{addr: addr, log: log, recorder: recorder}
}
func (s *Server) Packets() uint64 { return s.packets.Load() }
func (s *Server) Serve(ctx context.Context) error {
	conn, err := net.ListenPacket("udp", s.addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	go func() { <-ctx.Done(); _ = conn.Close() }()
	buffer := make([]byte, 2048)
	for {
		n, remote, err := conn.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.packets.Add(1)
		_ = s.recorder.Record("nat", "in", remote.String(), buffer[:n])
		response, _ := json.Marshal(map[string]any{"observed_address": remote.String(), "research_only": true, "unix": time.Now().Unix()})
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.WriteTo(response, remote); err != nil {
			s.log.Warn("nat response failed", "remote", remote, "error", err)
		}
	}
}
