package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/josh/mw2-rpcs3/internal/protocol"
)

const (
	ServiceID uint8 = 1
	TaskLogin uint8 = 1
)

type Service struct{ secret [32]byte }

func New() (*Service, error) {
	service := &Service{}
	if _, err := rand.Read(service.secret[:]); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *Service) Register(dispatcher *protocol.Dispatcher) error {
	return dispatcher.Register(ServiceID, TaskLogin, s.login)
}

func (s *Service) login(_ context.Context, request protocol.Frame) (protocol.Frame, error) {
	decoder := protocol.NewDecoder(request.Payload, 4096)
	npid, err := decoder.String()
	if err != nil || npid == "" {
		return protocol.Frame{Kind: protocol.KindError, Payload: errorPayload("invalid_identity")}, errors.New("invalid identity")
	}
	build, err := decoder.String()
	if err != nil || build != "BLUS30377-1.14" {
		return protocol.Frame{Kind: protocol.KindError, Payload: errorPayload("unsupported_build")}, errors.New("unsupported build")
	}
	userHash := sha256.Sum256([]byte(npid))
	userID := binary.BigEndian.Uint64(userHash[:8])
	expires := uint64(time.Now().Add(12 * time.Hour).Unix())
	mac := hmac.New(sha256.New, s.secret[:])
	_ = binary.Write(mac, binary.BigEndian, userID)
	_ = binary.Write(mac, binary.BigEndian, expires)
	var encoder protocol.Encoder
	encoder.Uint64(userID)
	encoder.Uint64(expires)
	encoder.Bytes(mac.Sum(nil))
	return protocol.Frame{Payload: encoder.Data()}, nil
}

func errorPayload(code string) []byte {
	var encoder protocol.Encoder
	encoder.String(code)
	return encoder.Data()
}
