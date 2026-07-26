package sessions

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/josh/mw2-rpcs3/internal/protocol"
)

const (
	ServiceID     uint8 = 3
	TaskCreate    uint8 = 1
	TaskFind      uint8 = 2
	TaskJoin      uint8 = 3
	TaskLeave     uint8 = 4
	TaskHeartbeat uint8 = 5
)

type Session struct {
	ID          string
	HostID      uint64
	HostAddress string
	JoinData    []byte
	Capacity    uint16
	Members     map[uint64]struct{}
	UpdatedAt   time.Time
}

type Service struct {
	mu       sync.RWMutex
	ttl      time.Duration
	now      func() time.Time
	sessions map[string]*Session
}

func New(ttl time.Duration) *Service {
	return &Service{ttl: ttl, now: time.Now, sessions: make(map[string]*Session)}
}
func (s *Service) Register(d *protocol.Dispatcher) error {
	for _, item := range []struct {
		task    uint8
		handler protocol.Handler
	}{{TaskCreate, s.create}, {TaskFind, s.find}, {TaskJoin, s.join}, {TaskLeave, s.leave}, {TaskHeartbeat, s.heartbeat}} {
		if err := d.Register(ServiceID, item.task, item.handler); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) create(_ context.Context, request protocol.Frame) (protocol.Frame, error) {
	d := protocol.NewDecoder(request.Payload, 64*1024)
	id, err := d.String()
	if err != nil || id == "" {
		return errorFrame("invalid_session"), errors.New("invalid session")
	}
	hostID, err := d.Uint64()
	if err != nil {
		return errorFrame("invalid_host"), err
	}
	address, err := d.String()
	if err != nil {
		return errorFrame("invalid_address"), err
	}
	capacity, err := d.Uint16()
	if err != nil || capacity < 2 || capacity > 18 {
		return errorFrame("invalid_capacity"), errors.New("invalid capacity")
	}
	joinData, err := d.Bytes()
	if err != nil {
		return errorFrame("invalid_join_data"), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	if _, exists := s.sessions[id]; exists {
		return errorFrame("already_exists"), errors.New("session exists")
	}
	s.sessions[id] = &Session{ID: id, HostID: hostID, HostAddress: address, JoinData: append([]byte(nil), joinData...), Capacity: capacity, Members: map[uint64]struct{}{hostID: {}}, UpdatedAt: s.now()}
	return encodeSession(s.sessions[id]), nil
}

func (s *Service) find(_ context.Context, _ protocol.Frame) (protocol.Frame, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var enc protocol.Encoder
	enc.Uint16(uint16(len(ids)))
	for _, id := range ids {
		encodeSessionInto(&enc, s.sessions[id])
	}
	return protocol.Frame{Payload: enc.Data()}, nil
}

func (s *Service) join(_ context.Context, request protocol.Frame) (protocol.Frame, error) {
	d := protocol.NewDecoder(request.Payload, 4096)
	id, err := d.String()
	if err != nil {
		return errorFrame("invalid_session"), err
	}
	userID, err := d.Uint64()
	if err != nil {
		return errorFrame("invalid_user"), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked()
	session := s.sessions[id]
	if session == nil {
		return errorFrame("not_found"), errors.New("session not found")
	}
	if _, exists := session.Members[userID]; !exists && len(session.Members) >= int(session.Capacity) {
		return errorFrame("full"), errors.New("session full")
	}
	session.Members[userID] = struct{}{}
	session.UpdatedAt = s.now()
	return encodeSession(session), nil
}

func (s *Service) leave(_ context.Context, request protocol.Frame) (protocol.Frame, error) {
	d := protocol.NewDecoder(request.Payload, 4096)
	id, err := d.String()
	if err != nil {
		return errorFrame("invalid_session"), err
	}
	userID, err := d.Uint64()
	if err != nil {
		return errorFrame("invalid_user"), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessions[id]
	if session == nil {
		return errorFrame("not_found"), errors.New("session not found")
	}
	if userID == session.HostID {
		delete(s.sessions, id)
	} else {
		delete(session.Members, userID)
		session.UpdatedAt = s.now()
	}
	return protocol.Frame{Payload: []byte{}}, nil
}

func (s *Service) heartbeat(_ context.Context, request protocol.Frame) (protocol.Frame, error) {
	d := protocol.NewDecoder(request.Payload, 4096)
	id, err := d.String()
	if err != nil {
		return errorFrame("invalid_session"), err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.sessions[id]
	if session == nil {
		return errorFrame("not_found"), errors.New("session not found")
	}
	session.UpdatedAt = s.now()
	return encodeSession(session), nil
}

func (s *Service) cleanupLocked() {
	cutoff := s.now().Add(-s.ttl)
	for id, session := range s.sessions {
		if session.UpdatedAt.Before(cutoff) {
			delete(s.sessions, id)
		}
	}
}
func encodeSession(session *Session) protocol.Frame {
	var enc protocol.Encoder
	encodeSessionInto(&enc, session)
	return protocol.Frame{Payload: enc.Data()}
}
func encodeSessionInto(enc *protocol.Encoder, session *Session) {
	enc.String(session.ID)
	enc.Uint64(session.HostID)
	enc.String(session.HostAddress)
	enc.Bytes(session.JoinData)
	enc.Uint16(session.Capacity)
	enc.Uint16(uint16(len(session.Members)))
	enc.Uint64(uint64(session.UpdatedAt.Unix()))
}
func errorFrame(code string) protocol.Frame {
	var enc protocol.Encoder
	enc.String(code)
	return protocol.Frame{Kind: protocol.KindError, Payload: enc.Data()}
}
