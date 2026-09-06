package auth

import (
	"path/filepath"
	"testing"
)

func buildMW2StatsWriteRequest(writeType uint8, boardID int32, entityID uint64, rating int64, columns ...int32) []byte {
	writer := newBDBitWriter()
	writer.writeU8(bdStatsWrite)
	writer.writeU8(0)
	writer.writeU8(writeType)
	writer.writeI32(boardID)
	writer.writeU64(entityID)
	writer.writeI64(rating)
	for _, column := range columns {
		writer.writeI32(column)
	}
	return writer.bytes()
}

func buildMW2StatsReadRequest(boardID int32, entityIDs ...uint64) []byte {
	writer := newBDBitWriter()
	writer.writeU8(bdStatsReadByEntity)
	writer.writeU8(0)
	writer.writeI32(boardID)
	writer.writeU32(uint32(len(entityIDs)))
	for _, entityID := range entityIDs {
		writer.writeU64(entityID)
	}
	return writer.bytes()
}

func TestMW2StatsWriteReadAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	store, err := newMW2StatsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := newLSGConnection(candidateSessionKey)
	if err != nil {
		t.Fatal(err)
	}
	connection.stats = store
	connection.entityID = legacyUserID
	columns := []int32{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	_, reply, handled := connection.handleStatsTask(buildMW2StatsWriteRequest(0, 2064, 0, 12345, columns...))
	if !handled || !connection.lastTaskSupported {
		t.Fatalf("handled=%v supported=%v reply=%x", handled, connection.lastTaskSupported, reply)
	}
	if err := store.close(); err != nil {
		t.Fatal(err)
	}
	store, err = newMW2StatsStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	connection.stats = store
	_, reply, handled = connection.handleStatsTask(buildMW2StatsReadRequest(2064, legacyUserID))
	if !handled || !connection.lastTaskSupported {
		t.Fatalf("handled=%v supported=%v reply=%x", handled, connection.lastTaskSupported, reply)
	}
	reader, err := newBDTaskReplyReader(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.readU64(); err != nil {
		t.Fatal(err)
	}
	if code, err := reader.readU32(); err != nil || code != bdErrorNone {
		t.Fatalf("error=%d err=%v", code, err)
	}
	if operation, err := reader.readU8(); err != nil || operation != bdStatsReadByEntity {
		t.Fatalf("operation=%d err=%v", operation, err)
	}
	if returned, err := reader.readU32(); err != nil || returned != 1 {
		t.Fatalf("returned=%d err=%v", returned, err)
	}
	if total, err := reader.readU32(); err != nil || total != 1 {
		t.Fatalf("total=%d err=%v", total, err)
	}
	entityID, err := reader.readU64()
	if err != nil || entityID != legacyUserID {
		t.Fatalf("entity=%x err=%v", entityID, err)
	}
	rating, err := reader.readI64()
	if err != nil || rating != 12345 {
		t.Fatalf("rating=%d err=%v", rating, err)
	}
	rank, err := reader.readU64()
	if err != nil || rank != 1 {
		t.Fatalf("rank=%d err=%v", rank, err)
	}
	name, err := reader.readString(64)
	if err != nil || name != legacyUsername {
		t.Fatalf("name=%q err=%v", name, err)
	}
	for index, want := range columns {
		got, err := reader.readI32()
		if err != nil || got != want {
			t.Fatalf("column[%d]=%d want=%d err=%v", index, got, want, err)
		}
	}
}

func TestMW2StatsRankingUsesRatingDescending(t *testing.T) {
	store, err := newMW2StatsStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	rows := []mw2StatsRow{
		{boardID: 1, entityID: 3, rating: 100, columns: [mw2StatsColumnCount]int32{}},
		{boardID: 1, entityID: 1, rating: 300, columns: [mw2StatsColumnCount]int32{}},
		{boardID: 1, entityID: 2, rating: 200, columns: [mw2StatsColumnCount]int32{}},
	}
	for _, row := range rows {
		if err := store.replace(row); err != nil {
			t.Fatal(err)
		}
	}
	got, err := store.readByEntity(1, []uint64{3, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	wantEntities := []uint64{1, 2, 3}
	for index, want := range wantEntities {
		if got[index].entityID != want || got[index].rank != uint64(index+1) {
			t.Fatalf("row[%d] entity=%d rank=%d", index, got[index].entityID, got[index].rank)
		}
	}
}
