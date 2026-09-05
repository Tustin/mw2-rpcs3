package bandwidth

import (
	"sync"
	"time"
)

type Results struct {
	BytesReceived   uint32
	ReceivePeriodMS uint32
	AverageSequence uint32
	MinimumSequence uint32
	MaximumSequence uint32
}

type measurement struct {
	first     time.Time
	last      time.Time
	sequences map[uint32]struct{}
	bytes     uint32
}

type Store struct {
	mu           sync.Mutex
	measurements map[string]measurement
}

func NewStore() *Store {
	return &Store{measurements: make(map[string]measurement)}
}

func (s *Store) Reset(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.measurements, key)
}

func (s *Store) Record(key string, sequence uint32, bytes uint32, receivedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.measurements[key]
	if current.sequences == nil {
		current = measurement{
			first:     receivedAt,
			last:      receivedAt,
			sequences: make(map[uint32]struct{}),
		}
	}
	if _, exists := current.sequences[sequence]; exists {
		return
	}
	current.sequences[sequence] = struct{}{}
	current.bytes += bytes
	if receivedAt.Before(current.first) {
		current.first = receivedAt
	}
	if receivedAt.After(current.last) {
		current.last = receivedAt
	}
	s.measurements[key] = current
}

func (s *Store) Consume(key string) (Results, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.measurements[key]
	delete(s.measurements, key)
	if len(current.sequences) == 0 {
		return Results{}, false
	}

	minimum := ^uint32(0)
	var maximum uint32
	var total uint64
	for sequence := range current.sequences {
		if sequence < minimum {
			minimum = sequence
		}
		if sequence > maximum {
			maximum = sequence
		}
		total += uint64(sequence)
	}
	period := current.last.Sub(current.first).Milliseconds()
	if period < 1 {
		period = 1
	}
	if period > int64(^uint32(0)) {
		period = int64(^uint32(0))
	}
	return Results{
		BytesReceived:   current.bytes,
		ReceivePeriodMS: uint32(period),
		AverageSequence: uint32(total / uint64(len(current.sequences))),
		MinimumSequence: minimum,
		MaximumSequence: maximum,
	}, true
}
