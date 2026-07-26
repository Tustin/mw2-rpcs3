package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/josh/mw2-rpcs3/internal/protocol"
)

const (
	ServiceID uint8 = 2
	TaskGet   uint8 = 1
)

type Service struct {
	mu    sync.RWMutex
	files map[string][]byte
}

func New(motd string) *Service {
	return &Service{files: map[string][]byte{
		"motd":     []byte(motd),
		"playlist": []byte("private_match_only=1\nsource=independently_authored\n"),
	}}
}

func (s *Service) Register(dispatcher *protocol.Dispatcher) error {
	return dispatcher.Register(ServiceID, TaskGet, s.get)
}
func (s *Service) get(_ context.Context, request protocol.Frame) (protocol.Frame, error) {
	decoder := protocol.NewDecoder(request.Payload, 1024)
	name, err := decoder.String()
	if err != nil {
		return protocol.Frame{Kind: protocol.KindError}, err
	}
	s.mu.RLock()
	value, ok := s.files[name]
	s.mu.RUnlock()
	if !ok {
		var enc protocol.Encoder
		enc.String("not_found")
		return protocol.Frame{Kind: protocol.KindError, Payload: enc.Data()}, errors.New("storage object not found")
	}
	var enc protocol.Encoder
	enc.String(name)
	enc.Bytes(value)
	return protocol.Frame{Payload: enc.Data()}, nil
}
