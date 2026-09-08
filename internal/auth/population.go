package auth

import "sync"

type PlaylistPopulation struct {
	PlaylistID int32  `json:"playlistId"`
	Players    uint64 `json:"players"`
	Sessions   uint64 `json:"sessions"`
}

type PopulationSnapshot struct {
	OnlinePlayers     uint64               `json:"onlinePlayers"`
	AdvertisedPlayers uint64               `json:"advertisedPlayers"`
	Sessions          uint64               `json:"sessions"`
	Playlists         []PlaylistPopulation `json:"playlists"`
}

type populationTracker struct {
	mu          sync.RWMutex
	connections map[uint64]uint64
}

func newPopulationTracker() *populationTracker {
	return &populationTracker{connections: make(map[uint64]uint64)}
}

func (t *populationTracker) connected(connectionID uint64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.connections[connectionID] = 0
	t.mu.Unlock()
}

func (t *populationTracker) identified(connectionID, entityID uint64) {
	if t == nil || entityID == 0 {
		return
	}
	t.mu.Lock()
	if _, ok := t.connections[connectionID]; ok {
		t.connections[connectionID] = entityID
	}
	t.mu.Unlock()
}

func (t *populationTracker) disconnected(connectionID uint64) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.connections, connectionID)
	t.mu.Unlock()
}

func (t *populationTracker) onlinePlayers() uint64 {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	entities := make(map[uint64]struct{}, len(t.connections))
	anonymous := uint64(0)
	for _, entityID := range t.connections {
		if entityID == 0 {
			anonymous++
			continue
		}
		entities[entityID] = struct{}{}
	}
	return uint64(len(entities)) + anonymous
}

func (s *RawServer) Population() PopulationSnapshot {
	population := s.matchmakingStore().population()
	population.OnlinePlayers = s.population.onlinePlayers()
	return population
}
