package auth

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

func buildMW2StorageListRequest() []byte {
	return buildMW2StorageListRequestWith(0, 30, "")
}

func buildMW2StorageListRequestWith(offset uint32, maximum uint16, filter string) []byte {
	writer := newLSBBitWriter(0)
	writer.writeBit(true)
	bd := &bdBitWriter{bits: writer}
	bd.writeU8(bdStorageListFiles)
	bd.writeU8(0)
	bd.writeU32(offset)
	bd.writeU16(maximum)
	if filter != "" {
		bd.writeString(filter)
	}
	writer.writeBits(0, 5)
	return bd.bytes()
}

func buildMW2StorageGetRequest(fileID uint64) []byte {
	writer := newLSBBitWriter(0)
	writer.writeBit(true)
	bd := &bdBitWriter{bits: writer}
	bd.writeU8(bdStorageGetFile)
	bd.writeU64(fileID)
	writer.writeBits(0, 5)
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

func mustBDTaskReplyReader(t *testing.T, payload []byte) *bdBitReader {
	t.Helper()
	reader, err := newBDTaskReplyReader(payload)
	if err != nil {
		t.Fatal(err)
	}
	return reader
}

func assertMW2FileInfo(t *testing.T, reader *bdBitReader) {
	assertMW2FileInfoValue(t, reader, mw2PlaylistFileID, mw2PlaylistFilename)
}

func assertMW2FileInfoValue(t *testing.T, reader *bdBitReader, expectedID uint64, expectedName string) {
	t.Helper()
	if fileID, err := reader.readU64(); err != nil || fileID != expectedID {
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
	if filename, err := readBDTestString(reader); err != nil || filename != expectedName {
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
	if request.operationID != bdStorageListFiles || request.value != 0 || request.offset != 0 || request.maximum != 100 || request.filter != "" {
		t.Fatalf("list request=%+v", request)
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

	malformedGet := buildMW2StorageGetRequest(mw2PlaylistFileID)
	malformedGet[len(malformedGet)-1] |= 0x08
	if _, err := parseMW2StorageRequest(malformedGet); err == nil {
		t.Fatalf("accepted nonzero op5 terminator: %x", malformedGet)
	}
}

func TestParseMW2StorageListRequestWithFilter(t *testing.T) {
	request, err := parseMW2StorageRequest(buildMW2StorageListRequestWith(0, 100, mw2PlaylistFilename))
	if err != nil {
		t.Fatal(err)
	}
	if request.operationID != bdStorageListFiles || request.value != 0 || request.offset != 0 || request.maximum != 100 || request.filter != mw2PlaylistFilename {
		t.Fatalf("request=%+v", request)
	}
}

func TestMW2StorageListHonorsFilterAndPagination(t *testing.T) {
	connection := &lsgConnection{}
	requests := [][]byte{
		buildMW2StorageListRequestWith(0, 100, "other.info"),
		buildMW2StorageListRequestWith(0, 0, ""),
		buildMW2StorageListRequestWith(2, 100, ""),
	}
	for index, request := range requests {
		_, reply, handled := connection.handleStorageTask(request)
		if !handled {
			t.Fatalf("request %d was not handled", index)
		}
		summary, err := parseMW2StorageReplySummary(reply)
		if err != nil {
			t.Fatalf("request %d: %v", index, err)
		}
		if summary.errorCode != bdErrorNone || summary.operationID != bdStorageListFiles || summary.resultCount != 0 || summary.fileSize != 0 {
			t.Fatalf("request %d summary=%+v", index, summary)
		}
	}

	_, reply, handled := connection.handleStorageTask(buildMW2StorageListRequestWith(0, 100, mw2PlaylistFilename))
	if !handled {
		t.Fatal("exact filename request was not handled")
	}
	summary, err := parseMW2StorageReplySummary(reply)
	if err != nil {
		t.Fatal(err)
	}
	if summary.resultCount != 1 {
		t.Fatalf("exact filename summary=%+v", summary)
	}

	_, reply, handled = connection.handleStorageTask(buildMW2StorageListRequestWith(0, 100, mw2MOTDFilename))
	if !handled {
		t.Fatal("exact MOTD filename request was not handled")
	}
	summary, err = parseMW2StorageReplySummary(reply)
	if err != nil {
		t.Fatal(err)
	}
	if summary.resultCount != 1 || summary.fileSize != uint32(len(mw2DefaultMOTD)) {
		t.Fatalf("exact MOTD filename summary=%+v", summary)
	}
}

func TestMW2PublisherDirectoryAdvertisesMOTDBeforePlaylist(t *testing.T) {
	playlist := []byte("version 504\n")
	files := []mw2PublisherFile{
		{id: mw2MOTDFileID, name: mw2MOTDFilename, data: []byte(mw2DefaultMOTD)},
		{id: mw2PlaylistFileID, name: mw2PlaylistFilename, data: playlist},
	}
	payload := (&lsgConnection{}).storagePublisherListReply(files)
	reader := mustBDTaskReplyReader(t, payload)
	if transaction, err := reader.readU64(); err != nil || transaction != 0 {
		t.Fatalf("transaction=%d err=%v", transaction, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("error=%d err=%v", errorCode, err)
	}
	if operation, err := reader.readU8(); err != nil || operation != bdStorageListFiles {
		t.Fatalf("operation=%d err=%v", operation, err)
	}
	if count, err := reader.readU32(); err != nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	if size, err := reader.readU32(); err != nil || size != uint32(len(mw2DefaultMOTD)) {
		t.Fatalf("MOTD size=%d err=%v", size, err)
	}
	assertMW2FileInfoValue(t, reader, mw2MOTDFileID, mw2MOTDFilename)
	if size, err := reader.readU32(); err != nil || size != uint32(len(playlist)) {
		t.Fatalf("playlist size=%d err=%v", size, err)
	}
	assertMW2FileInfoValue(t, reader, mw2PlaylistFileID, mw2PlaylistFilename)
}

func TestMW2StorageGetReplyContainsMOTDBlob(t *testing.T) {
	motd := []byte("Server test message")
	file := mw2PublisherFile{id: mw2MOTDFileID, name: mw2MOTDFilename, data: motd}
	payload := (&lsgConnection{}).storagePublisherGetReply(file)
	reader := mustBDTaskReplyReader(t, payload)
	if _, err := reader.readU64(); err != nil {
		t.Fatal(err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("error=%d err=%v", errorCode, err)
	}
	if operation, err := reader.readU8(); err != nil || operation != bdStorageGetFile {
		t.Fatalf("operation=%d err=%v", operation, err)
	}
	if size, err := reader.readU32(); err != nil || size != uint32(len(motd)) {
		t.Fatalf("size=%d err=%v", size, err)
	}
	assertMW2FileInfoValue(t, reader, mw2MOTDFileID, mw2MOTDFilename)
	blob, err := reader.readBlob(mw2MOTDMaxSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, motd) {
		t.Fatalf("blob=%q", blob)
	}
}

func TestParseMW2StorageListReplySummary(t *testing.T) {
	connection, err := newLSGConnection([24]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	playlist := []byte("version 504\n")
	summary, err := parseMW2StorageReplySummary(connection.storageListReply(playlist))
	if err != nil {
		t.Fatal(err)
	}
	if summary.transactionID != 0 || summary.errorCode != bdErrorNone || summary.operationID != bdStorageListFiles || summary.resultCount != 1 || summary.fileSize != uint32(len(playlist)) {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestMW2StorageOwnerListReplyIsSuccessfulAndEmpty(t *testing.T) {
	connection := &lsgConnection{nextTransaction: 4}
	summary, err := parseMW2StorageReplySummary(connection.storageOwnerListReply())
	if err != nil {
		t.Fatal(err)
	}
	if summary.transactionID != 4 || summary.errorCode != bdErrorNone || summary.operationID != bdStorageListOwnerFiles || summary.resultCount != 0 || summary.fileSize != 0 {
		t.Fatalf("summary=%+v", summary)
	}
}

func TestNormalAndStorageRepliesShareTransactionSequence(t *testing.T) {
	connection := &lsgConnection{}
	normal := connection.taskReply(6, bdErrorNone, nil)
	if transaction := binary.LittleEndian.Uint64(normal[1:9]); transaction != 0 {
		t.Fatalf("normal transaction=%d", transaction)
	}
	storage, err := parseMW2StorageReplySummary(connection.storageListReply([]byte("version 504\n")))
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
	playlist := []byte("version 504\n")
	connection := &lsgConnection{nextTransaction: 1}
	payload := connection.storageListReply(playlist)
	reader := mustBDTaskReplyReader(t, payload)
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
	fileSize, err := reader.readU32()
	if err != nil {
		t.Fatal(err)
	}
	if transaction != 1 || errorCode != bdErrorNone || operation != bdStorageListFiles || count != 1 || fileSize != uint32(len(playlist)) {
		t.Fatalf("transaction=%d error=%d operation=%d count=%d file_size=%d payload=%x", transaction, errorCode, operation, count, fileSize, payload)
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
	reader := mustBDTaskReplyReader(t, payload)
	if transaction, err := reader.readU64(); err != nil || transaction != 7 {
		t.Fatalf("transaction=%d err=%v", transaction, err)
	}
	if errorCode, err := reader.readU32(); err != nil || errorCode != bdErrorNone {
		t.Fatalf("error=%d err=%v", errorCode, err)
	}
	if operation, err := reader.readU8(); err != nil || operation != bdStorageGetFile {
		t.Fatalf("operation=%d err=%v", operation, err)
	}
	if fileSize, err := reader.readU32(); err != nil || fileSize != uint32(len(playlist)) {
		t.Fatalf("file size=%d err=%v", fileSize, err)
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

func TestMW2StorageRepliesMatchRecoveredGoldenLayouts(t *testing.T) {
	// These literals were independently encoded from the retail consumers:
	// the type-checking marker at 0x003d2be8/0x003d2810, op 8 at
	// 0x003eb4a8, op 5 at 0x003ea690, and FileInfo at 0x003eca78.
	listWant, err := hex.DecodeString("15000000000000000002000000180828000000000d00000028c43bb32aa2199108040000008000000000824001000000000000004038b6b03cb6b439ba39973437b33700")
	if err != nil {
		t.Fatal(err)
	}
	listGot := (&lsgConnection{}).storageListReply([]byte("ABC"))
	if !bytes.Equal(listGot, listWant) {
		t.Fatalf("op8 reply=%x want=%x", listGot, listWant)
	}

	getWant, err := hex.DecodeString("150000000000000000020000001805680000004021de995511cd884420000000000400000010040a0000000000000000c2b185e5b1a5cdd1cdb9a4b999bd014c3400000010243404")
	if err != nil {
		t.Fatal(err)
	}
	getGot := (&lsgConnection{}).storageGetReply([]byte("ABC"))
	if !bytes.Equal(getGot, getWant) {
		t.Fatalf("op5 reply=%x want=%x", getGot, getWant)
	}
}

func TestMW2TaskRepliesRequireTypeCheckingMarker(t *testing.T) {
	reply := (&lsgConnection{}).storageListReply([]byte("ABC"))
	if reply[0]&1 != 1 {
		t.Fatalf("reply is missing leading type-checking marker: %x", reply)
	}
	if _, err := newBDTaskReplyReader(reply); err != nil {
		t.Fatalf("marked reply was rejected: %v", err)
	}

	// This is the pre-fix op 8 payload observed in the live server trace. The
	// client consumes its low zero bit as the type-checking flag, then decodes
	// the remaining fields one bit out of alignment.
	markerless, err := hex.DecodeString("0a0000000000000000010000000c0414000000800600000014e29d5915d18c480402000000400000000041a00000000000000000201c5b581e5bda1cdd9c4b9a9bd91b00")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newBDTaskReplyReader(markerless); err == nil {
		t.Fatal("accepted markerless task reply")
	}
}

func TestMW2StorageListThenGetActualPlaylist(t *testing.T) {
	playlist, err := os.ReadFile("../../playlists.info")
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/playlists.info"
	if err := os.WriteFile(path, playlist, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MW2_PLAYLISTS_FILE", path)

	connection := &lsgConnection{}
	observedListRequest, err := hex.DecodeString("07c2004000000000860c0000")
	if err != nil {
		t.Fatal(err)
	}
	responseType, listReply, handled := connection.handleStorageTask(observedListRequest)
	if !handled || responseType != lsgTaskReplyType || !connection.lastTaskSupported {
		t.Fatalf("op8 type=%d handled=%v supported=%v payload=%x", responseType, handled, connection.lastTaskSupported, listReply)
	}
	listSummary, err := parseMW2StorageReplySummary(listReply)
	if err != nil {
		t.Fatal(err)
	}
	if listSummary.transactionID != 0 || listSummary.operationID != bdStorageListFiles || listSummary.resultCount != 2 || listSummary.fileSize != uint32(len(mw2DefaultMOTD)) {
		t.Fatalf("op8 summary=%+v playlist_bytes=%d", listSummary, len(playlist))
	}

	responseType, getReply, handled := connection.handleStorageTask(buildMW2StorageGetRequest(mw2PlaylistFileID))
	if !handled || responseType != lsgTaskReplyType || !connection.lastTaskSupported {
		t.Fatalf("op5 type=%d handled=%v supported=%v payload=%x", responseType, handled, connection.lastTaskSupported, getReply)
	}
	reader := mustBDTaskReplyReader(t, getReply)
	if transaction, readErr := reader.readU64(); readErr != nil || transaction != 1 {
		t.Fatalf("op5 transaction=%d err=%v", transaction, readErr)
	}
	if errorCode, readErr := reader.readU32(); readErr != nil || errorCode != bdErrorNone {
		t.Fatalf("op5 error=%d err=%v", errorCode, readErr)
	}
	if operation, readErr := reader.readU8(); readErr != nil || operation != bdStorageGetFile {
		t.Fatalf("op5 operation=%d err=%v", operation, readErr)
	}
	if fileSize, readErr := reader.readU32(); readErr != nil || fileSize != uint32(len(playlist)) {
		t.Fatalf("op5 file_size=%d err=%v", fileSize, readErr)
	}
	assertMW2FileInfo(t, reader)
	if err := reader.readType(bdTypeBlob); err != nil {
		t.Fatal(err)
	}
	blobLength, err := reader.readU32()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := reader.bits.readBytes(int(blobLength))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob, playlist) {
		t.Fatalf("op5 blob differs: got=%d want=%d", len(blob), len(playlist))
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
