package auth

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

func TestMW2MatchmakingStoreDeepCopiesSessionData(t *testing.T) {
	commonAddress := bytes.Repeat([]byte{0x11}, mw2MatchmakingCommonAddressSize)
	sessionID := bytes.Repeat([]byte{0x22}, mw2MatchmakingSessionIDSize)
	securityKey := bytes.Repeat([]byte{0x33}, mw2MatchmakingSecurityKeySize)
	info := mw2MatchmakingInfo{
		commonAddress: commonAddress,
		sessionID:     sessionID,
		securityKey:   securityKey,
		openPublic:    18,
		filledPublic:  1,
		attributes:    [9]int32{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}
	store := newMW2MatchmakingStore()
	created, err := store.create(info, 1)
	if err != nil {
		t.Fatal(err)
	}
	commonAddress[0] = 0xff
	sessionID[0] = 0xff
	securityKey[0] = 0xff

	found := store.find(1, 0, false)
	if len(found) != 1 || found[0].commonAddress[0] != 0x11 {
		t.Fatalf("stored data aliases request buffers: %+v", found)
	}
	if found[0].sessionID != created.sessionID || found[0].securityKey != created.securityKey {
		t.Fatalf("generated identity changed: got=%+v created=%+v", found[0], created)
	}

	exported := found[0].info()
	exported.commonAddress[0] = 0xee
	exported.sessionID[0] = 0xee
	exported.securityKey[0] = 0xee
	again := store.find(1, 0, false)
	if again[0].commonAddress[0] != 0x11 ||
		again[0].sessionID != created.sessionID ||
		again[0].securityKey != created.securityKey {
		t.Fatalf("stored data aliases exported buffers: %+v", again[0])
	}
}

func TestMW2MatchmakingStoreSortsAndCapsByCreationOrder(t *testing.T) {
	store := newMW2MatchmakingStore()
	store.sessions[[mw2MatchmakingSessionIDSize]byte{1}] = mw2StoredMatchmakingSession{
		sessionID:     [mw2MatchmakingSessionIDSize]byte{1},
		creationOrder: 3,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{3}] = mw2StoredMatchmakingSession{
		sessionID:     [mw2MatchmakingSessionIDSize]byte{3},
		creationOrder: 1,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{2}] = mw2StoredMatchmakingSession{
		sessionID:     [mw2MatchmakingSessionIDSize]byte{2},
		creationOrder: 2,
	}
	found := store.find(2, 0, false)
	if len(found) != 2 || found[0].sessionID[0] != 3 || found[1].sessionID[0] != 2 {
		t.Fatalf("find order/cap=%+v", found)
	}
}

func TestMW2MatchmakingStoreReturnsSelfInclusiveSessionsInCreationOrder(t *testing.T) {
	store := newMW2MatchmakingStore()
	validInfo := func() mw2MatchmakingInfo {
		return mw2MatchmakingInfo{
			commonAddress: make([]byte, mw2MatchmakingCommonAddressSize),
			sessionID:     make([]byte, mw2MatchmakingSessionIDSize),
			securityKey:   make([]byte, mw2MatchmakingSecurityKeySize),
			openPublic:    8,
		}
	}
	first, err := store.create(validInfo(), 7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.create(validInfo(), 8)
	if err != nil {
		t.Fatal(err)
	}
	third, err := store.create(validInfo(), 9)
	if err != nil {
		t.Fatal(err)
	}

	found := store.find(3, 0, false)
	if len(found) != 3 ||
		found[0].sessionID != first.sessionID ||
		found[1].sessionID != second.sessionID ||
		found[2].sessionID != third.sessionID {
		t.Fatalf("self-inclusive creation order=%+v", found)
	}

	firstInfo := first.info()
	firstInfo.openPublic = 0
	if _, ok := store.update(firstInfo, 7); !ok {
		t.Fatal("failed to update first session")
	}
	found = store.find(3, 0, false)
	if len(found) != 3 || found[0].sessionID != first.sessionID {
		t.Fatalf("update changed creation order: %+v", found)
	}
}

func TestMW2MatchmakingStoreExcludesOwnerBeforeCapping(t *testing.T) {
	store := newMW2MatchmakingStore()
	store.sessions[[mw2MatchmakingSessionIDSize]byte{1}] = mw2StoredMatchmakingSession{
		sessionID: [mw2MatchmakingSessionIDSize]byte{1},
		ownerID:   7,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{2}] = mw2StoredMatchmakingSession{
		sessionID: [mw2MatchmakingSessionIDSize]byte{2},
		ownerID:   8,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{3}] = mw2StoredMatchmakingSession{
		sessionID: [mw2MatchmakingSessionIDSize]byte{3},
		ownerID:   9,
	}

	found := store.findExcludingOwner(1, 0, false, 7)
	if len(found) != 1 || found[0].sessionID[0] != 2 {
		t.Fatalf("owner-filtered sessions=%+v", found)
	}
}

func TestMW2MatchmakingStoreRequiresEnoughOpenPublicSlots(t *testing.T) {
	store := newMW2MatchmakingStore()
	store.sessions[[mw2MatchmakingSessionIDSize]byte{1}] = mw2StoredMatchmakingSession{
		sessionID:  [mw2MatchmakingSessionIDSize]byte{1},
		openPublic: 1,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{2}] = mw2StoredMatchmakingSession{
		sessionID:  [mw2MatchmakingSessionIDSize]byte{2},
		openPublic: 2,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{3}] = mw2StoredMatchmakingSession{
		sessionID:  [mw2MatchmakingSessionIDSize]byte{3},
		openPublic: 3,
	}

	found := store.find(50, 2, false)
	if len(found) != 2 || found[0].sessionID[0] != 2 || found[1].sessionID[0] != 3 {
		t.Fatalf("slot-filtered sessions=%+v", found)
	}
}

func TestMW2MatchmakingStoreCanSearchOpenPrivateSlots(t *testing.T) {
	store := newMW2MatchmakingStore()
	store.sessions[[mw2MatchmakingSessionIDSize]byte{1}] = mw2StoredMatchmakingSession{
		sessionID:   [mw2MatchmakingSessionIDSize]byte{1},
		openPublic:  8,
		openPrivate: 1,
	}
	store.sessions[[mw2MatchmakingSessionIDSize]byte{2}] = mw2StoredMatchmakingSession{
		sessionID:   [mw2MatchmakingSessionIDSize]byte{2},
		openPublic:  1,
		openPrivate: 3,
	}

	found := store.find(50, 2, true)
	if len(found) != 1 || found[0].sessionID[0] != 2 {
		t.Fatalf("private-slot-filtered sessions=%+v", found)
	}
}

func TestMW2MatchmakingStoreEnforcesOwnerAndCapacity(t *testing.T) {
	store := newMW2MatchmakingStoreWithLimit(1)
	info := mw2MatchmakingInfo{
		commonAddress: make([]byte, mw2MatchmakingCommonAddressSize),
		sessionID:     make([]byte, mw2MatchmakingSessionIDSize),
		securityKey:   make([]byte, mw2MatchmakingSecurityKeySize),
		openPublic:    1,
	}
	const ownerID = uint64(0x1122334455667788)
	created, err := store.create(info, ownerID)
	if err != nil {
		t.Fatal(err)
	}

	updated := created.info()
	updated.openPublic = 2
	if _, ok := store.update(updated, ownerID+1); ok {
		t.Fatal("different LSG connection updated a session it did not create")
	}
	if store.delete(created.sessionID[:], ownerID+1) {
		t.Fatal("different LSG connection deleted a session it did not create")
	}
	if _, ok := store.update(updated, ownerID); !ok {
		t.Fatal("owning LSG connection could not update its session")
	}

	if _, err := store.create(info, ownerID); err == nil {
		t.Fatal("store accepted a session beyond its configured capacity")
	}
	if !store.delete(created.sessionID[:], ownerID) {
		t.Fatal("owning LSG connection could not delete its session")
	}
	if _, err := store.create(info, ownerID); err != nil {
		t.Fatalf("capacity was not released after deletion: %v", err)
	}
}

func TestMW2MatchmakingStoreReclaimsOnlyClosedConnectionOwner(t *testing.T) {
	store := newMW2MatchmakingStoreWithLimit(2)
	info := mw2MatchmakingInfo{
		commonAddress: make([]byte, mw2MatchmakingCommonAddressSize),
		sessionID:     make([]byte, mw2MatchmakingSessionIDSize),
		securityKey:   make([]byte, mw2MatchmakingSecurityKeySize),
		openPublic:    1,
	}
	first, err := store.create(info, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.create(info, 2)
	if err != nil {
		t.Fatal(err)
	}

	if removed := store.deleteOwner(1); removed != 1 {
		t.Fatalf("removed=%d, want 1", removed)
	}
	found := store.find(2, 0, false)
	if len(found) != 1 || found[0].sessionID != second.sessionID {
		t.Fatalf("owner cleanup removed the wrong sessions: %+v", found)
	}
	if store.delete(first.sessionID[:], 1) {
		t.Fatal("owner cleanup left the first session addressable")
	}
	if _, err := store.create(info, 3); err != nil {
		t.Fatalf("owner cleanup did not release capacity: %v", err)
	}
}

func TestMW2MatchmakingStoreRejectsInvalidDirectInput(t *testing.T) {
	store := newMW2MatchmakingStore()
	invalid := mw2MatchmakingInfo{
		commonAddress: make([]byte, mw2MatchmakingCommonAddressSize-1),
		sessionID:     make([]byte, mw2MatchmakingSessionIDSize),
		securityKey:   make([]byte, mw2MatchmakingSecurityKeySize),
	}
	if _, err := store.create(invalid, 1); err == nil {
		t.Fatal("create accepted a short common-address blob")
	}
	if _, ok := store.update(invalid, 1); ok {
		t.Fatal("update accepted a short common-address blob")
	}
}

func TestMW2MatchmakingStoreWaitsForSecondEligibleSession(t *testing.T) {
	store := newMW2MatchmakingStore()
	info := mw2MatchmakingInfo{
		commonAddress: bytes.Repeat([]byte{0x11}, mw2MatchmakingCommonAddressSize),
		sessionID:     make([]byte, mw2MatchmakingSessionIDSize),
		securityKey:   make([]byte, mw2MatchmakingSecurityKeySize),
		openPrivate:   8,
		attributes:    [9]int32{1},
	}
	first, err := store.create(info, 1)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan []mw2StoredMatchmakingSession, 1)
	go func() {
		result <- store.findWaitingForSearchResults(50, mw2MatchmakingSearch{requiredFreeSlots: 1, gameType: 1}, 2, time.Second)
	}()
	select {
	case found := <-result:
		t.Fatalf("find returned before second session: %x", found)
	case <-time.After(20 * time.Millisecond):
	}
	second, err := store.create(info, 2)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case found := <-result:
		if len(found) != 2 || found[0].sessionID != first.sessionID || found[1].sessionID != second.sessionID {
			t.Fatalf("found=%x want=%x,%x", found, first.sessionID, second.sessionID)
		}
	case <-time.After(time.Second):
		t.Fatal("find did not wake after second session")
	}
}

func TestMW2MatchmakingStoreWaitTimesOutWithSoloSession(t *testing.T) {
	store := newMW2MatchmakingStore()
	info := mw2MatchmakingInfo{
		commonAddress: bytes.Repeat([]byte{0x11}, mw2MatchmakingCommonAddressSize),
		sessionID:     make([]byte, mw2MatchmakingSessionIDSize),
		securityKey:   make([]byte, mw2MatchmakingSecurityKeySize),
		openPrivate:   8,
		attributes:    [9]int32{1},
	}
	created, err := store.create(info, 1)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	found := store.findWaitingForSearchResults(50, mw2MatchmakingSearch{requiredFreeSlots: 1, gameType: 1}, 2, 20*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 15*time.Millisecond {
		t.Fatalf("find returned too early after %s", elapsed)
	}
	if len(found) != 1 || found[0].sessionID != created.sessionID {
		t.Fatalf("found=%x want=%x", found, created.sessionID)
	}
}

func TestMW2MatchmakingStoreConcurrentLifecycle(t *testing.T) {
	store := newMW2MatchmakingStore()
	var wait sync.WaitGroup
	for worker := 0; worker < 64; worker++ {
		wait.Add(1)
		go func(value byte) {
			defer wait.Done()
			info := mw2MatchmakingInfo{
				commonAddress: bytes.Repeat([]byte{value}, mw2MatchmakingCommonAddressSize),
				sessionID:     bytes.Repeat([]byte{0xaa}, mw2MatchmakingSessionIDSize),
				securityKey:   bytes.Repeat([]byte{0xbb}, mw2MatchmakingSecurityKeySize),
				openPublic:    int32(value),
				attributes:    [9]int32{int32(value)},
			}
			ownerID := uint64(value)
			created, err := store.create(info, ownerID)
			if err != nil {
				t.Errorf("create: %v", err)
				return
			}
			updated := created.info()
			updated.filledPublic = int32(value)
			if _, ok := store.update(updated, ownerID); !ok {
				t.Errorf("update %x failed", created.sessionID)
			}
			_ = store.find(10, 0, false)
			if !store.delete(created.sessionID[:], ownerID) {
				t.Errorf("delete %x failed", created.sessionID)
			}
		}(byte(worker + 1))
	}
	wait.Wait()
	if found := store.find(50, 0, false); len(found) != 0 {
		t.Fatalf("%d sessions remained after concurrent lifecycle", len(found))
	}
}
