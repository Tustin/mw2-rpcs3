package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/josh/mw2-rpcs3/internal/capture"
	"github.com/josh/mw2-rpcs3/internal/protocol"
)

type TCPServer struct {
	name, addr                string
	log                       *slog.Logger
	dispatcher                *protocol.Dispatcher
	recorder                  *capture.Recorder
	maxFrame                  uint32
	readTimeout, writeTimeout time.Duration
	connections               atomic.Uint64
	requests                  atomic.Uint64
}

func NewTCP(name, addr string, log *slog.Logger, dispatcher *protocol.Dispatcher, recorder *capture.Recorder, maxFrame uint32, readTimeout, writeTimeout time.Duration) *TCPServer {
	return &TCPServer{name: name, addr: addr, log: log, dispatcher: dispatcher, recorder: recorder, maxFrame: maxFrame, readTimeout: readTimeout, writeTimeout: writeTimeout}
}
func (s *TCPServer) Connections() uint64 { return s.connections.Load() }
func (s *TCPServer) Requests() uint64    { return s.requests.Load() }
func (s *TCPServer) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	var wg sync.WaitGroup
	var connectionsMu sync.Mutex
	connections := make(map[net.Conn]struct{})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		connectionsMu.Lock()
		defer connectionsMu.Unlock()
		for conn := range connections {
			_ = conn.Close()
		}
	}()
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.connections.Add(1)
		connectionsMu.Lock()
		connections[conn] = struct{}{}
		connectionsMu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				connectionsMu.Lock()
				delete(connections, conn)
				connectionsMu.Unlock()
			}()
			s.handle(ctx, conn)
		}()
	}
}
func (s *TCPServer) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log := s.log.With("listener", s.name, "remote", remote)
	log.Info("client connected")
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))
		request, err := protocol.ReadFrame(conn, s.maxFrame)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isTimeout(err) {
				log.Warn("frame read failed", "error", err)
			}
			return
		}
		s.requests.Add(1)
		if encoded, encodeErr := protocol.MarshalFrame(request, s.maxFrame); encodeErr == nil {
			_ = s.recorder.Record(s.name, "in", remote, encoded)
		}
		response, dispatchErr := s.dispatcher.Dispatch(ctx, request)
		if dispatchErr != nil {
			log.Warn("request dispatch", "service", request.Service, "task", request.Task, "transaction", request.Transaction, "error", dispatchErr)
		}
		if encoded, encodeErr := protocol.MarshalFrame(response, s.maxFrame); encodeErr == nil {
			_ = s.recorder.Record(s.name, "out", remote, encoded)
		}
		_ = conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
		if err := protocol.WriteFrame(conn, response, s.maxFrame); err != nil {
			log.Warn("frame write failed", "error", err)
			return
		}
	}
}
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
