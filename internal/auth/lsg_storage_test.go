package auth

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func buildMW2StorageListRequest() []byte {
	writer := newLSBBitWriter(0)
	writer.writeBit(true)
	bd := &bdBitWriter{bits: writer}
	bd.writeU8(bdStorageListFiles)
	bd.writeU8(1)
	bd.writeU32(0)
	bd.writeU16(30)
	return bd.bytes()
}

func buildMW2StorageGetRequest(fileID uint64) []byte {
	writer := newLSBBitWriter(0)
	writer.writeBit(true)
	bd := &bdBitWriter{bits: writer}
	bd.writeU8(bdStorageGetFile)
	bd.writeU64(fileID)
	return bd.bytes()
}

func readBDTestString(reader *bdBitReader) (string, error) {
	if err := reader.readType(bdTypeString); err != nil {
		return "", err
	}
	var value []byte
	for {
		character, err := reader.bits.readBits(8)
		if err != nil {
			return "", err
		}
		if character == 0 {
			return string(value), nil
		}
		value = append(value, byte(character))
	}
}

func assertMW2FileInfo(t *testing.T, reader *bdBitReader) {
	t.Helper()
	if fileID, err := reader.readU64(); err != nil || fileID != mw2PlaylistFileID {
		t.Fatalf("file=%x err=%v", fileID, err)
	}
	if value, err := reader.readU32(); err != nil || value != 0 {
		t.Fatalf("value 1=%d err=%v", value, err)
	}
	if value, err := reader.readU32(); err != nil || value != 0 {
		t.Fatalf("value 2=%d err=%v", value, err)
	}
	for index := 1; index <= 2; index++ {
		if err := reader.readType(bdTypeBool); err != nil {
			t.Fatal(err)
		}
		if value, err := reader.bits.readBits(1); err != nil || value != 0 {
			t.Fatalf("flag %d=%d err=%v", index, value, err)
		}
	}
	if value, err := reader.readU64(); err != nil || value != 0 {
		t.Fatalf("value 3=%x err=%v", value, err)
	}
	if filename, err := readBDTestString(reader); err != nil || filename != mw2PlaylistFilename {
		t.Fatalf("filename=%q err=%v", filename, err)
	}
}

func TestParseObservedMW2StorageOwnerListRequest(t *testing.T) {
	payload := []byte{
		0xc7, 0xc1, 0x00, 0x50, 0xfa, 0xda, 0xe3, 0x5e, 0x3e, 0xd1,
		0x04, 0xb8, 0x08, 0x00, 0x00, 0x00, 0xc0, 0x90, 0x01, 0x00,
	}
	request, err := parseMW2StorageRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if request.operationID != bdStorageListOwnerFiles || request.ownerID != 0xb804d13e5ee3dafa || request.offset != 0 || request.maximum != 100 {
		t.Fatalf("request=%+v", request)
	}
}

func TestParseObservedMW2StorageListRequest(t *testing.T) {
	payload := []byte{
		0x07, 0xc2, 0x00, 0x40, 0x00, 0x00,
		0x00, 0x00, 0x86, 0x0c, 0x00, 0x00,
	}
	request, err := parseMW2StorageRequest(payload)
	if err != nil {
		t.Fatal(err)
	}
	if payload[0] == bdStorageListFiles {
		t.Fatal("bit-packed request payload must not be decoded byte-aligned")
	}
	if request.operationID != bdStorageListFiles {
		t.Fatalf("list operation=%d", request.operationID)
	}
}

func TestParseMW2StorageRequests(t *testing.T) {
	list, err := parseMW2StorageRequest(buildMW2StorageListRequest())
	if err != nil {
		t.Fatal(err)
	}
	if list.operationID != bdStorageListFiles {
		t.Fatalf("list operation=%d", list.operationID)
	}

	get, err := parseMW2StorageRequest(buildMW2StorageGetRequest(mw2PlaylistFileID))
	if err != nil {
		t.Fatal(err)
	}
	if get.operationID != bdStorageGetFile || get.fileID != mw2PlaylistFileID {
		t.Fatalf("get=%+v", get)
	}
}

func TestParseMW2StorageListReplySummary(t *testing.T) {
	connection, err := newLSGConnection([24]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	summary, err := parseMW2StorageReplySummary(connection.storageListReply())
	if err != nil {
		t.Fatal(err)
	}
	if summary.transactionID != 0 || summary.errorCode != bdErrorNone || summary.operationID != bdStorageListFiles || summary.resultCount != 1 || summary.totalResultCount != 1 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestMW2StorageOwnerListReplyIsSuccessfulAndEmpty(t *testing.T) {
	connection := &lsgConnection{nextTransaction: 4}
	summary, err := parseMW2StorageReplySummary(connection.storageOwnerListReply())
	if err != nil {
		t.Fatal(err)
	}
	if summary.transactionID != 4 || summary.errorCode != bdErrorNone || summary.operationID != bdStorageListOwnerFiles || summary.resultCount != 0 || summary.totalResultCount != 0 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestNormalAndStorageRepliesShareTransactionSequence(t *testing.T) {
	connection := &lsgConnection{}
	normal := connection.taskReply(6, bdErrorNone, nil)
	if transaction := binary.LittleEndian.Uint64(normal[1:9]); transaction != 0 {
		t.Fatalf("normal transaction=%d", transaction)
	}
	storage, err := parseMW2StorageReplySummary(connection.storageListReply())
	if err != nil {
		t.Fatal(err)
	}
	if storage.transactionID != 1 {
		t.Fatalf("storage transaction=%d", storage.transactionID)
	}
}

func TestSeparateStorageTasksReceiveDistinctTransactions(t *testing.T) {
	connection := &lsgConnection{}
	request := buildMW2StorageListRequest()
	_, first, ok := connection.handleStorageTask(request)
	if !ok {
		t.Fatal("first storage request was not handled")
	}
	secondRequest := append(append([]byte(nil), request...), bytes.Repeat([]byte{0x1f}, 8)...)
	_, second, ok := connection.handleStorageTask(secondRequest)
	if !ok {
		t.Fatal("second storage request was not handled")
	}
	firstSummary, err := parseMW2StorageReplySummary(first)
	if err != nil {
		t.Fatal(err)
	}
	secondSummary, err := parseMW2StorageReplySummary(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstSummary.transactionID != 0 || secondSummary.transactionID != 1 {
		t.Fatalf("transactions=%d,%d", firstSummary.transactionID, secondSummary.transactionID)
	}
}

func TestMW2StorageListReplyAdvertisesPlaylist(t *testing.T) {
	connection := &lsgConnection{nextTransaction: 1}
	payload := connection.storageListReply()
	reader := newBDBitReader(payload)
	transaction, err := reader.readU64()
	if err != nil {
		t.Fatal(err)
	}
	errorCode, err := reader.readU32()
	if err != nil {
		t.Fatal(err)
	}
	operation, err := reader.readU8()
	if err != nil {
		t.Fatal(err)
	}
	count, err := reader.readU32()
	if err != nil {
		t.Fatal(err)
	}
	totalCount, err := reader.readU32()
	if err != nil {
		t.Fatal(err)
	}
	if transaction != 1 || errorCode != bdErrorNone || operation != bdStorageListFiles || count != 1 || totalCount != 1 {
		t.Fatalf("transaction=%d error=%d operation=%d count=%d total=%d payload=%x", transaction, errorCode, operation, count, totalCount, payload)
	}
	assertMW2FileInfo(t, reader)

	if len(payload) != 68 {
		t.Fatalf("payload length=%d payload=%x", len(payload), payload)
	}
}

func TestMW2StorageGetReplyContainsPlaylistBlob(t *testing.T) {
	playlist := []byte("version 504\n\ngametype dm\nname english \"Free-for-All\"\nscript dm\n")
	connection := &lsgConnection{nextTransaction: 7}
	payload := connection.storageGetReply(playlist)
	reader := newBDBitReader(payload)
	if transaction, err := reader.readU64(); err != nil || transaction != 7 {
		t.Fatalf("transaction=%d err=%v", transaction, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("error=%d err=%v", errorCode, err)
	}
	if operation, err := reader.readU8(); err != nil || operation != bdStorageGetFile {
		t.Fatalf("operation=%d err=%v", operation, err)
	}
	if count, err := reader.readU32(); err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if totalCount, err := reader.readU32(); err != nil || totalCount != 1 {
		t.Fatalf("total count=%d err=%v", totalCount, err)
	}
	assertMW2FileInfo(t, reader)
	if err := reader.readType(bdTypeBlob); err != nil {
		t.Fatal(err)
	}
	length, err := reader.readU32()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := reader.bits.readBytes(int(length))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, playlist) {
		t.Fatalf("blob=%q", blob)
	}
}

func TestEncryptLSGServerRecordUsesDeadBeefPrefix(t *testing.T) {
	frame, err := EncryptLSGServerRecord(lsgTaskReplyType, []byte{1, 2, 3}, 0x12345678, candidateSessionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptLSGRecord(frame, candidateSessionKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if decrypted.HMAC != 0xdeadbeef || decrypted.HMACValid {
		t.Fatalf("prefix=%08x valid=%v plaintext=%x", decrypted.HMAC, decrypted.HMACValid, decrypted.Plaintext)
	}
	if binary.LittleEndian.Uint32(decrypted.Plaintext[:4]) != 0xdeadbeef {
		t.Fatalf("plaintext prefix=%x", decrypted.Plaintext[:4])
	}
}

func TestLoadMW2PlaylistHonorsConfiguredPathAndLimit(t *testing.T) {
	path := t.TempDir() + "/playlists.info"
	want := []byte("version 504\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MW2_PLAYLISTS_FILE", path)
	got, err := loadMW2Playlist()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("playlist=%q", got)
	}
}
