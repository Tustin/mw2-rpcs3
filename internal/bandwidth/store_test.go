package bandwidth

import (
	"testing"
	"time"
)

func TestStoreConsume(t *testing.T) {
	store := NewStore()
	startedAt := time.Unix(1_700_000_000, 0)
	store.Record("client-a", 4, 512, startedAt.Add(2*time.Second))
	store.Record("client-a", 0, 512, startedAt)
	store.Record("client-a", 2, 512, startedAt.Add(time.Second))
	store.Record("client-a", 2, 512, startedAt.Add(time.Second))

	results, ok := store.Consume("client-a")
	if !ok {
		t.Fatal("measurement was not available")
	}
	if results.BytesReceived != 1536 || results.ReceivePeriodMS != 2000 || results.AverageSequence != 2 || results.MinimumSequence != 0 || results.MaximumSequence != 4 {
		t.Fatalf("results=%+v", results)
	}
	if _, ok := store.Consume("client-a"); ok {
		t.Fatal("measurement was not consumed")
	}
}

func TestStoreSeparatesClients(t *testing.T) {
	store := NewStore()
	store.Record("client-a", 0, 512, time.Unix(1_700_000_000, 0))
	store.Record("client-b", 4, 512, time.Unix(1_700_000_001, 0))

	results, ok := store.Consume("client-b")
	if !ok || results.MinimumSequence != 4 || results.MaximumSequence != 4 {
		t.Fatalf("results=%+v ok=%v", results, ok)
	}
	if _, ok := store.Consume("client-a"); !ok {
		t.Fatal("consuming client-b removed client-a")
	}
}

func TestStoreConsumeEmpty(t *testing.T) {
	if _, ok := NewStore().Consume("client-a"); ok {
		t.Fatal("empty store returned a measurement")
	}
}
