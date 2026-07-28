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
	fileID, err := reader.readU64()
	if err != nil {
		t.Fatal(err)
	}
	if transaction != 1 || errorCode != bdErrorNone || operation != bdStorageListFiles || count != 1 || fileID != mw2PlaylistFileID {
		t.Fatalf("transaction=%d error=%d operation=%d count=%d file=%x payload=%x", transaction, errorCode, operation, count, fileID, payload)
	}
	for _, expected := range []struct {
		tag  byte
		bits int
	}{{bdTypeU32, 32}, {bdTypeU32, 32}, {bdTypeBool, 1}, {bdTypeBool, 1}, {bdTypeU64, 64}} {
		if err := reader.readType(expected.tag); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.bits.readBits(expected.bits); err != nil {
			t.Fatal(err)
		}
	}
	if err := reader.readType(bdTypeString); err != nil {
		t.Fatal(err)
	}
	var filename []byte
	for {
		value, err := reader.bits.readBits(8)
		if err != nil {
			t.Fatal(err)
		}
		if value == 0 {
			break
		}
		filename = append(filename, byte(value))
	}
	if string(filename) != mw2PlaylistFilename {
		t.Fatalf("filename=%q payload=%x", filename, payload)
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
	if fileID, err := reader.readU64(); err != nil || fileID != mw2PlaylistFileID {
		t.Fatalf("file=%x err=%v", fileID, err)
	}
	for _, expected := range []struct {
		tag  byte
		bits int
	}{{bdTypeU32, 32}, {bdTypeU32, 32}, {bdTypeBool, 1}, {bdTypeBool, 1}, {bdTypeU64, 64}} {
		if err := reader.readType(expected.tag); err != nil {
			t.Fatal(err)
		}
		if _, err := reader.bits.readBits(expected.bits); err != nil {
			t.Fatal(err)
		}
	}
	if err := reader.readType(bdTypeString); err != nil {
		t.Fatal(err)
	}
	filename := make([]byte, 0, len(mw2PlaylistFilename))
	for {
		value, err := reader.bits.readBits(8)
		if err != nil {
			t.Fatal(err)
		}
		if value == 0 {
			break
		}
		filename = append(filename, byte(value))
	}
	if string(filename) != mw2PlaylistFilename {
		t.Fatalf("filename=%q", filename)
	}
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
