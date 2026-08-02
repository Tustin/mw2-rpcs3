package auth

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"
	"sync"
)

const defaultMW2MatchmakingSessionLimit = 4096

type mw2StoredMatchmakingSession struct {
	commonAddress [mw2MatchmakingCommonAddressSize]byte
	sessionID     [mw2MatchmakingSessionIDSize]byte
	securityKey   [mw2MatchmakingSecurityKeySize]byte
	openPublic    int32
	filledPublic  int32
	openPrivate   int32
	filledPrivate int32
	attributes    [9]int32
	ownerID       uint64
	creationOrder uint64
}

type mw2MatchmakingStore struct {
	mu                sync.RWMutex
	maxSessions       int
	nextCreationOrder uint64
	sessions          map[[mw2MatchmakingSessionIDSize]byte]mw2StoredMatchmakingSession
}

func newMW2MatchmakingStore() *mw2MatchmakingStore {
	return newMW2MatchmakingStoreWithLimit(defaultMW2MatchmakingSessionLimit)
}

func newMW2MatchmakingStoreWithLimit(maxSessions int) *mw2MatchmakingStore {
	if maxSessions < 1 {
		maxSessions = 1
	}
	return &mw2MatchmakingStore{
		maxSessions: maxSessions,
		sessions:    make(map[[mw2MatchmakingSessionIDSize]byte]mw2StoredMatchmakingSession),
	}
}

func matchmakingSessionFromInfo(info mw2MatchmakingInfo) mw2StoredMatchmakingSession {
	var session mw2StoredMatchmakingSession
	copy(session.commonAddress[:], info.commonAddress)
	copy(session.sessionID[:], info.sessionID)
	copy(session.securityKey[:], info.securityKey)
	session.openPublic = info.openPublic
	session.filledPublic = info.filledPublic
	session.openPrivate = info.openPrivate
	session.filledPrivate = info.filledPrivate
	session.attributes = info.attributes
	return session
}

func (s mw2StoredMatchmakingSession) info() mw2MatchmakingInfo {
	return mw2MatchmakingInfo{
		commonAddress: append([]byte(nil), s.commonAddress[:]...),
		sessionID:     append([]byte(nil), s.sessionID[:]...),
		securityKey:   append([]byte(nil), s.securityKey[:]...),
		openPublic:    s.openPublic,
		filledPublic:  s.filledPublic,
		openPrivate:   s.openPrivate,
		filledPrivate: s.filledPrivate,
		attributes:    s.attributes,
	}
}

func (s *mw2MatchmakingStore) create(info mw2MatchmakingInfo, ownerID uint64) (mw2StoredMatchmakingSession, error) {
	if s == nil {
		return mw2StoredMatchmakingSession{}, fmt.Errorf("matchmaking store is nil")
	}
	if err := validateMW2MatchmakingInfoLengths(info); err != nil {
		return mw2StoredMatchmakingSession{}, err
	}
	session := matchmakingSessionFromInfo(info)
	session.ownerID = ownerID
	for {
		if _, err := rand.Read(session.sessionID[:]); err != nil {
			return mw2StoredMatchmakingSession{}, fmt.Errorf("generate matchmaking session ID: %w", err)
		}
		if allZero(session.sessionID[:]) {
			continue
		}
		if _, err := rand.Read(session.securityKey[:]); err != nil {
			return mw2StoredMatchmakingSession{}, fmt.Errorf("generate matchmaking security key: %w", err)
		}
		if allZero(session.securityKey[:]) {
			continue
		}

		s.mu.Lock()
		if len(s.sessions) >= s.maxSessions {
			s.mu.Unlock()
			return mw2StoredMatchmakingSession{}, fmt.Errorf(
				"matchmaking session capacity %d reached",
				s.maxSessions,
			)
		}
		if _, exists := s.sessions[session.sessionID]; !exists {
			s.nextCreationOrder++
			session.creationOrder = s.nextCreationOrder
			s.sessions[session.sessionID] = session
			s.mu.Unlock()
			return session, nil
		}
		s.mu.Unlock()
	}
}

func (s *mw2MatchmakingStore) update(info mw2MatchmakingInfo, ownerID uint64) (mw2StoredMatchmakingSession, bool) {
	if s == nil || validateMW2MatchmakingInfoLengths(info) != nil {
		return mw2StoredMatchmakingSession{}, false
	}
	var sessionID [mw2MatchmakingSessionIDSize]byte
	copy(sessionID[:], info.sessionID)

	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[sessionID]
	if !ok || current.ownerID != ownerID {
		return mw2StoredMatchmakingSession{}, false
	}
	copy(current.commonAddress[:], info.commonAddress)
	current.openPublic = info.openPublic
	current.filledPublic = info.filledPublic
	current.openPrivate = info.openPrivate
	current.filledPrivate = info.filledPrivate
	current.attributes = info.attributes
	s.sessions[sessionID] = current
	return current, true
}

func (s *mw2MatchmakingStore) delete(sessionIDValue []byte, ownerID uint64) bool {
	if s == nil || len(sessionIDValue) != mw2MatchmakingSessionIDSize {
		return false
	}
	var sessionID [mw2MatchmakingSessionIDSize]byte
	copy(sessionID[:], sessionIDValue)

	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok || session.ownerID != ownerID {
		return false
	}
	delete(s.sessions, sessionID)
	return true
}

func (s *mw2MatchmakingStore) deleteOwner(ownerID uint64) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for sessionID, session := range s.sessions {
		if session.ownerID == ownerID {
			delete(s.sessions, sessionID)
			removed++
		}
	}
	return removed
}

func (s *mw2MatchmakingStore) find(
	maxResults int32,
	requiredFreeSlots int32,
	usePrivateSlots bool,
) []mw2StoredMatchmakingSession {
	return s.findMatching(maxResults, requiredFreeSlots, usePrivateSlots, 0, false)
}

func (s *mw2MatchmakingStore) findExcludingOwner(
	maxResults int32,
	requiredFreeSlots int32,
	usePrivateSlots bool,
	ownerID uint64,
) []mw2StoredMatchmakingSession {
	return s.findMatching(maxResults, requiredFreeSlots, usePrivateSlots, ownerID, true)
}

func (s *mw2MatchmakingStore) findMatching(
	maxResults int32,
	requiredFreeSlots int32,
	usePrivateSlots bool,
	excludedOwnerID uint64,
	excludeOwner bool,
) []mw2StoredMatchmakingSession {
	if s == nil || maxResults <= 0 {
		return nil
	}
	s.mu.RLock()
	result := make([]mw2StoredMatchmakingSession, 0, len(s.sessions))
	for _, session := range s.sessions {
		if excludeOwner && session.ownerID == excludedOwnerID {
			continue
		}
		openSlots := session.openPublic
		if usePrivateSlots {
			openSlots = session.openPrivate
		}
		if openSlots >= requiredFreeSlots {
			result = append(result, session)
		}
	}
	s.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool {
		if result[i].creationOrder != result[j].creationOrder {
			return result[i].creationOrder < result[j].creationOrder
		}
		return bytes.Compare(result[i].sessionID[:], result[j].sessionID[:]) < 0
	})
	if int64(len(result)) > int64(maxResults) {
		result = result[:maxResults]
	}
	return result
}

func validateMW2MatchmakingInfoLengths(info mw2MatchmakingInfo) error {
	switch {
	case len(info.commonAddress) != mw2MatchmakingCommonAddressSize:
		return fmt.Errorf(
			"common address length is %d, expected %d",
			len(info.commonAddress),
			mw2MatchmakingCommonAddressSize,
		)
	case len(info.sessionID) != mw2MatchmakingSessionIDSize:
		return fmt.Errorf(
			"session ID length is %d, expected %d",
			len(info.sessionID),
			mw2MatchmakingSessionIDSize,
		)
	case len(info.securityKey) != mw2MatchmakingSecurityKeySize:
		return fmt.Errorf(
			"security key length is %d, expected %d",
			len(info.securityKey),
			mw2MatchmakingSecurityKeySize,
		)
	default:
		return nil
	}
}

func allZero(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}
