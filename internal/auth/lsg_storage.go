package auth

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

const (
	mw2PlaylistFileID       = uint64(0x1122334455667788)
	mw2PlaylistFilename     = "playlists.info"
	mw2PlaylistPatch3FileID = uint64(0x112233445566778a)
	mw2PlaylistPatch3Name   = "playlists.patch3"
	mw2PlaylistMaxSize      = 0x20000
	mw2MOTDFileID           = uint64(0x1122334455667789)
	mw2MOTDFilename         = "messageoftheday.info"
	mw2MOTDMaxSize          = 0x100
	mw2DefaultMOTD          = "Welcome to Modern Warfare 2 multiplayer"
	bdStorageUploadUserFile = byte(1)
	bdStorageUpdateUserFile = byte(2)
	bdStorageGetFile        = byte(5)
	bdStorageListOwnerFiles = byte(7)
	bdStorageListFiles      = byte(8)
	mw2ProfileFilename      = "iw4-mpdata"
	mw2ProfileSize          = 0x2000
)

type mw2PublisherFile struct {
	id   uint64
	name string
	data []byte
}

type bdBitWriter struct {
	bits *lsbBitWriter
}

func newBDBitWriter() *bdBitWriter {
	writer := &bdBitWriter{bits: newLSBBitWriter(0)}
	// bdLobbyConnection constructs received task buffers as type-checked and
	// consumes this flag before bdRemoteTaskManager reads the first typed
	// value. Without it, the first bit of the U64 tag is consumed as the flag
	// and every reply field is decoded one bit out of alignment.
	writer.bits.writeBit(true)
	return writer
}

func (w *bdBitWriter) writeType(value byte) {
	w.bits.writeBits(uint64(value), 5)
}

func (w *bdBitWriter) writeBool(value bool) {
	w.writeType(bdTypeBool)
	w.bits.writeBit(value)
}

func (w *bdBitWriter) writeU8(value byte) {
	w.writeType(bdTypeU8)
	w.bits.writeBits(uint64(value), 8)
}

func (w *bdBitWriter) writeU16(value uint16) {
	w.writeType(bdTypeU16)
	w.bits.writeBits(uint64(value), 16)
}

func (w *bdBitWriter) writeI32(value int32) {
	w.writeType(bdTypeI32)
	w.bits.writeBits(uint64(uint32(value)), 32)
}

func (w *bdBitWriter) writeU32(value uint32) {
	w.writeType(bdTypeU32)
	w.bits.writeBits(uint64(value), 32)
}

func (w *bdBitWriter) writeRawU32(value uint32) {
	w.bits.writeBits(uint64(value), 32)
}

func (w *bdBitWriter) writeRawBEU32(value uint32) {
	w.bits.writeBytes([]byte{
		byte(value >> 24),
		byte(value >> 16),
		byte(value >> 8),
		byte(value),
	})
}

func (w *bdBitWriter) writeI64(value int64) {
	w.writeType(bdTypeI64)
	w.bits.writeBits(uint64(value), 64)
}

func (w *bdBitWriter) writeU64(value uint64) {
	w.writeType(bdTypeU64)
	w.bits.writeBits(value, 64)
}

func (w *bdBitWriter) writeString(value string) {
	w.writeType(bdTypeString)
	w.bits.writeBytes(append([]byte(value), 0))
}

func (w *bdBitWriter) writeBlob(value []byte) {
	w.writeType(bdTypeBlob)
	w.writeU32(uint32(len(value)))
	w.bits.writeBytes(value)
}

func (w *bdBitWriter) bytes() []byte {
	return w.bits.bytes()
}

type bdBitReader struct {
	bits *lsbBitReader
}

func newBDBitReader(data []byte) *bdBitReader {
	return &bdBitReader{bits: newLSBBitReader(data)}
}

func newBDTaskReplyReader(data []byte) (*bdBitReader, error) {
	reader := newBDBitReader(data)
	typeChecked, err := reader.bits.readBits(1)
	if err != nil {
		return nil, fmt.Errorf("read task reply type-checking marker: %w", err)
	}
	if typeChecked != 1 {
		return nil, fmt.Errorf("task reply is missing type-checking marker")
	}
	return reader, nil
}

func (r *bdBitReader) readType(expected byte) error {
	value, err := r.bits.readBits(5)
	if err != nil {
		return err
	}
	if byte(value) != expected {
		return fmt.Errorf("unexpected bd type %d, expected %d", value, expected)
	}
	return nil
}

func (r *bdBitReader) readBool() (bool, error) {
	if err := r.readType(bdTypeBool); err != nil {
		return false, err
	}
	value, err := r.bits.readBits(1)
	return value != 0, err
}

func (r *bdBitReader) readU8() (byte, error) {
	if err := r.readType(bdTypeU8); err != nil {
		return 0, err
	}
	value, err := r.bits.readBits(8)
	return byte(value), err
}

func (r *bdBitReader) readU16() (uint16, error) {
	if err := r.readType(bdTypeU16); err != nil {
		return 0, err
	}
	value, err := r.bits.readBits(16)
	return uint16(value), err
}

func (r *bdBitReader) readI32() (int32, error) {
	if err := r.readType(bdTypeI32); err != nil {
		return 0, err
	}
	value, err := r.bits.readBits(32)
	return int32(uint32(value)), err
}

func (r *bdBitReader) readU32() (uint32, error) {
	if err := r.readType(bdTypeU32); err != nil {
		return 0, err
	}
	value, err := r.bits.readBits(32)
	return uint32(value), err
}

func (r *bdBitReader) readI64() (int64, error) {
	if err := r.readType(bdTypeI64); err != nil {
		return 0, err
	}
	value, err := r.bits.readBits(64)
	return int64(value), err
}

func (r *bdBitReader) readU64() (uint64, error) {
	if err := r.readType(bdTypeU64); err != nil {
		return 0, err
	}
	return r.bits.readBits(64)
}

func (r *bdBitReader) readString(maximum int) (string, error) {
	if err := r.readType(bdTypeString); err != nil {
		return "", err
	}
	value := make([]byte, 0, maximum)
	for len(value) <= maximum {
		character, err := r.bits.readBits(8)
		if err != nil {
			return "", err
		}
		if character == 0 {
			return string(value), nil
		}
		value = append(value, byte(character))
	}
	return "", fmt.Errorf("string exceeds maximum %d", maximum)
}

func (r *bdBitReader) readBlob(maximum int) ([]byte, error) {
	if err := r.readType(bdTypeBlob); err != nil {
		return nil, err
	}
	length, err := r.readU32()
	if err != nil {
		return nil, err
	}
	if length > uint32(maximum) {
		return nil, fmt.Errorf("blob length %d exceeds maximum %d", length, maximum)
	}
	return r.bits.readBytes(int(length))
}

type mw2StorageRequest struct {
	operationID byte
	value       byte
	fileID      uint64
	ownerID     uint64
	offset      uint32
	maximum     uint16
	filter      string
	filename    string
	firstFlag   bool
	secondFlag  bool
	data        []byte
}

type mw2StorageReplySummary struct {
	transactionID uint64
	errorCode     uint32
	operationID   byte
	resultCount   uint32
	fileSize      uint32
}

type mw2UserFile struct {
	id      uint64
	ownerID uint64
	name    string
	data    []byte
}

type mw2UserFileStore struct {
	db *sql.DB
}

func newMW2UserFileStore(path string) (*mw2UserFileStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open profile database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS user_files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		owner_id BLOB NOT NULL UNIQUE,
		filename TEXT NOT NULL,
		data BLOB NOT NULL CHECK(length(data) = 8192)
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize profile database: %w", err)
	}
	return &mw2UserFileStore{db: db}, nil
}

func newMemoryMW2UserFileStore() *mw2UserFileStore {
	store, err := newMW2UserFileStore(":memory:")
	if err != nil {
		panic(err)
	}
	return store
}

func (s *mw2UserFileStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func userFileEntityKey(entityID uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, entityID)
	return key
}

func userFileEntityID(key []byte) (uint64, bool) {
	if len(key) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(key), true
}

func scanMW2UserFile(scanner interface{ Scan(...any) error }) (mw2UserFile, error) {
	var file mw2UserFile
	var ownerKey []byte
	var id int64
	if err := scanner.Scan(&id, &ownerKey, &file.name, &file.data); err != nil {
		return mw2UserFile{}, err
	}
	ownerID, ok := userFileEntityID(ownerKey)
	if !ok || id <= 0 || len(file.data) != mw2ProfileSize {
		return mw2UserFile{}, fmt.Errorf("invalid stored profile")
	}
	file.id = uint64(id)
	file.ownerID = ownerID
	file.data = append([]byte(nil), file.data...)
	return file, nil
}

func (s *mw2UserFileStore) upload(ownerID uint64, name string, data []byte) (mw2UserFile, error) {
	if _, err := s.db.Exec(`INSERT INTO user_files (owner_id, filename, data) VALUES (?, ?, ?)
		ON CONFLICT(owner_id) DO UPDATE SET filename = excluded.filename, data = excluded.data`, userFileEntityKey(ownerID), name, data); err != nil {
		return mw2UserFile{}, fmt.Errorf("store profile: %w", err)
	}
	file, ok, err := s.getByOwner(ownerID)
	if err != nil {
		return mw2UserFile{}, err
	}
	if !ok {
		return mw2UserFile{}, fmt.Errorf("stored profile is missing")
	}
	return file, nil
}

func (s *mw2UserFileStore) update(ownerID, fileID uint64, data []byte) (mw2UserFile, bool, error) {
	result, err := s.db.Exec(`UPDATE user_files SET data = ? WHERE id = ? AND owner_id = ?`, data, fileID, userFileEntityKey(ownerID))
	if err != nil {
		return mw2UserFile{}, false, fmt.Errorf("update profile: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return mw2UserFile{}, false, fmt.Errorf("read updated profile count: %w", err)
	}
	if rows == 0 {
		file, ok, err := s.getByOwner(ownerID)
		if err != nil || !ok || file.name != mw2ProfileFilename {
			return mw2UserFile{}, false, err
		}
		fileID = file.id
		if _, err := s.db.Exec(`UPDATE user_files SET data = ? WHERE id = ?`, data, fileID); err != nil {
			return mw2UserFile{}, false, fmt.Errorf("update owner profile: %w", err)
		}
	}
	file, ok, err := s.get(fileID)
	return file, ok, err
}

func (s *mw2UserFileStore) get(fileID uint64) (mw2UserFile, bool, error) {
	file, err := scanMW2UserFile(s.db.QueryRow(`SELECT id, owner_id, filename, data FROM user_files WHERE id = ?`, fileID))
	if err == sql.ErrNoRows {
		return mw2UserFile{}, false, nil
	}
	if err != nil {
		return mw2UserFile{}, false, fmt.Errorf("get profile: %w", err)
	}
	return file, true, nil
}

func (s *mw2UserFileStore) getByOwner(ownerID uint64) (mw2UserFile, bool, error) {
	file, err := scanMW2UserFile(s.db.QueryRow(`SELECT id, owner_id, filename, data FROM user_files WHERE owner_id = ?`, userFileEntityKey(ownerID)))
	if err == sql.ErrNoRows {
		return mw2UserFile{}, false, nil
	}
	if err != nil {
		return mw2UserFile{}, false, fmt.Errorf("get owner profile: %w", err)
	}
	return file, true, nil
}

func (s *mw2UserFileStore) list(ownerID uint64) ([]mw2UserFile, error) {
	rows, err := s.db.Query(`SELECT id, owner_id, filename, data FROM user_files WHERE owner_id = ? ORDER BY id`, userFileEntityKey(ownerID))
	if err != nil {
		return nil, fmt.Errorf("list owner profiles: %w", err)
	}
	defer rows.Close()
	files := make([]mw2UserFile, 0, 1)
	for rows.Next() {
		file, err := scanMW2UserFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan owner profile: %w", err)
		}
		files = append(files, file)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list owner profiles: %w", err)
	}
	return files, nil
}

func parseMW2StorageRequest(payload []byte) (mw2StorageRequest, error) {
	reader := newBDBitReader(payload)
	typeChecked, err := reader.bits.readBits(1)
	if err != nil || typeChecked != 1 {
		return mw2StorageRequest{}, fmt.Errorf("storage request is missing type-checking marker")
	}
	operationID, err := reader.readU8()
	if err != nil {
		return mw2StorageRequest{}, fmt.Errorf("read storage operation: %w", err)
	}
	request := mw2StorageRequest{operationID: operationID}
	switch operationID {
	case bdStorageUploadUserFile:
		request.value, err = reader.readU8()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage upload context: %w", err)
		}
		request.firstFlag, err = reader.readBool()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage upload first flag: %w", err)
		}
		request.filename, err = reader.readString(128)
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage upload filename: %w", err)
		}
		request.secondFlag, err = reader.readBool()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage upload second flag: %w", err)
		}
		request.data, err = reader.readBlob(mw2ProfileSize)
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage upload body: %w", err)
		}
	case bdStorageUpdateUserFile:
		request.value, err = reader.readU8()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage update context: %w", err)
		}
		request.fileID, err = reader.readU64()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage update file ID: %w", err)
		}
		request.data, err = reader.readBlob(mw2ProfileSize)
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage update body: %w", err)
		}
	case bdStorageListOwnerFiles:
		request.value, err = reader.readU8()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read owner file list value: %w", err)
		}
		request.ownerID, err = reader.readU64()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read owner file list owner: %w", err)
		}
		request.offset, err = reader.readU32()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read owner file list offset: %w", err)
		}
		request.maximum, err = reader.readU16()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read owner file list maximum: %w", err)
		}
	case bdStorageListFiles:
		request.value, err = reader.readU8()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage list value: %w", err)
		}
		request.offset, err = reader.readU32()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage list offset: %w", err)
		}
		request.maximum, err = reader.readU16()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage list maximum: %w", err)
		}
		nextType, readErr := reader.bits.readBits(5)
		if readErr != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage list filter type: %w", readErr)
		}
		switch byte(nextType) {
		case 0:
			// No optional filename filter.
		case bdTypeString:
			var filter []byte
			for {
				character, stringErr := reader.bits.readBits(8)
				if stringErr != nil {
					return mw2StorageRequest{}, fmt.Errorf("read storage list filter: %w", stringErr)
				}
				if character == 0 {
					break
				}
				if len(filter) >= 128 {
					return mw2StorageRequest{}, fmt.Errorf("storage list filter exceeds 128 bytes")
				}
				filter = append(filter, byte(character))
			}
			request.filter = string(filter)
			terminator, terminatorErr := reader.bits.readBits(5)
			if terminatorErr != nil {
				return mw2StorageRequest{}, fmt.Errorf("read storage list terminator: %w", terminatorErr)
			}
			if terminator != 0 {
				return mw2StorageRequest{}, fmt.Errorf("unexpected storage list terminator type %d", terminator)
			}
		default:
			return mw2StorageRequest{}, fmt.Errorf("unexpected storage list filter type %d", nextType)
		}
	case bdStorageGetFile:
		request.value, err = reader.readU8()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage get value: %w", err)
		}
		if request.value != 0 {
			return mw2StorageRequest{}, fmt.Errorf("unexpected storage get value %d", request.value)
		}
		request.fileID, err = reader.readU64()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage file ID: %w", err)
		}
		terminator, terminatorErr := reader.bits.readBits(5)
		if terminatorErr != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage get terminator: %w", terminatorErr)
		}
		if terminator != 0 {
			return mw2StorageRequest{}, fmt.Errorf("unexpected storage get terminator type %d", terminator)
		}
	}
	return request, nil
}

func parseMW2StorageReplySummary(payload []byte) (mw2StorageReplySummary, error) {
	reader, err := newBDTaskReplyReader(payload)
	if err != nil {
		return mw2StorageReplySummary{}, err
	}
	transactionID, err := reader.readU64()
	if err != nil {
		return mw2StorageReplySummary{}, fmt.Errorf("read storage reply transaction: %w", err)
	}
	errorCode, err := reader.readU32()
	if err != nil {
		return mw2StorageReplySummary{}, fmt.Errorf("read storage reply error: %w", err)
	}
	operationID, err := reader.readU8()
	if err != nil {
		return mw2StorageReplySummary{}, fmt.Errorf("read storage reply operation: %w", err)
	}
	summary := mw2StorageReplySummary{
		transactionID: transactionID,
		errorCode:     errorCode,
		operationID:   operationID,
	}
	if errorCode == bdErrorNone {
		switch operationID {
		case bdStorageUploadUserFile, bdStorageUpdateUserFile:
			summary.resultCount, err = reader.readU32()
			if err != nil {
				return mw2StorageReplySummary{}, fmt.Errorf("read storage mutation result count: %w", err)
			}
		case bdStorageListFiles, bdStorageListOwnerFiles:
			summary.resultCount, err = reader.readU32()
			if err != nil {
				return mw2StorageReplySummary{}, fmt.Errorf("read storage reply result count: %w", err)
			}
			if summary.resultCount != 0 {
				summary.fileSize, err = reader.readU32()
				if err != nil {
					return mw2StorageReplySummary{}, fmt.Errorf("read storage reply file size: %w", err)
				}
			}
		case bdStorageGetFile:
			summary.resultCount = 1
			summary.fileSize, err = reader.readU32()
			if err != nil {
				return mw2StorageReplySummary{}, fmt.Errorf("read storage reply file buffer size: %w", err)
			}
		}
	}
	return summary, nil
}

func (c *lsgConnection) nextTransactionID() uint64 {
	value := c.nextTransaction
	c.nextTransaction++
	return value
}

func writeMW2FileInfo(writer *bdBitWriter, file mw2PublisherFile) {
	writer.writeU64(file.id)
	writer.writeU32(0)
	writer.writeU32(0)
	writer.writeBool(false)
	writer.writeBool(false)
	writer.writeU64(0)
	writer.writeString(file.name)
}

func (c *lsgConnection) storageErrorReply(operationID byte, errorCode uint32) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(errorCode)
	writer.writeU8(operationID)
	return writer.bytes()
}

func (c *lsgConnection) storagePublisherListReply(files []mw2PublisherFile) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageListFiles)
	writer.writeU32(uint32(len(files)))
	for _, file := range files {
		writer.writeU32(uint32(len(file.data)))
		writeMW2FileInfo(writer, file)
	}
	return writer.bytes()
}

func (c *lsgConnection) storageListReply(data []byte) []byte {
	return c.storagePublisherListReply([]mw2PublisherFile{{
		id: mw2PlaylistFileID, name: mw2PlaylistFilename, data: data,
	}})
}

func (c *lsgConnection) storageEmptyListReply() []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageListFiles)
	writer.writeU32(0)
	return writer.bytes()
}

func writeMW2UserFileInfo(writer *bdBitWriter, file mw2UserFile) {
	writeMW2FileInfo(writer, mw2PublisherFile{id: file.id, name: file.name, data: file.data})
}

func (c *lsgConnection) storageOwnerListReply(files []mw2UserFile) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageListOwnerFiles)
	writer.writeU32(uint32(len(files)))
	for _, file := range files {
		writer.writeU32(uint32(len(file.data)))
		writeMW2UserFileInfo(writer, file)
	}
	return writer.bytes()
}

func (c *lsgConnection) storageMutationReply(operationID byte, fileID uint64) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(operationID)
	writer.writeU32(1)
	writer.writeU64(fileID)
	return writer.bytes()
}

func (c *lsgConnection) storageUserGetReply(file mw2UserFile) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageGetFile)
	writer.writeU32(uint32(len(file.data)))
	writeMW2UserFileInfo(writer, file)
	writer.writeBlob(file.data)
	return writer.bytes()
}

func (c *lsgConnection) storagePublisherGetReply(file mw2PublisherFile) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageGetFile)
	writer.writeU32(uint32(len(file.data)))
	writeMW2FileInfo(writer, file)
	writer.writeBlob(file.data)
	return writer.bytes()
}

func (c *lsgConnection) storageGetReply(data []byte) []byte {
	return c.storagePublisherGetReply(mw2PublisherFile{
		id: mw2PlaylistFileID, name: mw2PlaylistFilename, data: data,
	})
}

func loadMW2Playlist() ([]byte, error) {
	paths := []string{os.Getenv("MW2_PLAYLISTS_FILE"), mw2PlaylistFilename, "../../" + mw2PlaylistFilename}
	var lastErr error
	for _, path := range paths {
		if path == "" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			lastErr = err
			continue
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("playlist file %q is empty", path)
		}
		if len(data) > mw2PlaylistMaxSize {
			return nil, fmt.Errorf("playlist file %q is %d bytes, maximum is %d", path, len(data), mw2PlaylistMaxSize)
		}
		return data, nil
	}
	return nil, fmt.Errorf("read %s: %w", mw2PlaylistFilename, lastErr)
}

func loadMW2PublisherFiles() ([]mw2PublisherFile, error) {
	playlist, err := loadMW2Playlist()
	if err != nil {
		return nil, err
	}
	motd := []byte(os.Getenv("MW2_MOTD"))
	if len(motd) == 0 {
		motd = []byte(mw2DefaultMOTD)
	}
	if len(motd) > mw2MOTDMaxSize {
		return nil, fmt.Errorf("MW2_MOTD is %d bytes, maximum is %d", len(motd), mw2MOTDMaxSize)
	}
	return []mw2PublisherFile{
		{id: mw2MOTDFileID, name: mw2MOTDFilename, data: motd},
		{id: mw2PlaylistFileID, name: mw2PlaylistFilename, data: playlist},
		{id: mw2PlaylistPatch3FileID, name: mw2PlaylistPatch3Name, data: playlist},
	}, nil
}

func selectMW2PublisherFiles(files []mw2PublisherFile, request mw2StorageRequest) []mw2PublisherFile {
	selected := make([]mw2PublisherFile, 0, len(files))
	for _, file := range files {
		if request.filter == "" || request.filter == file.name {
			selected = append(selected, file)
		}
	}
	if request.maximum == 0 || request.offset >= uint32(len(selected)) {
		return nil
	}
	selected = selected[request.offset:]
	if len(selected) > int(request.maximum) {
		selected = selected[:request.maximum]
	}
	return selected
}

func findMW2PublisherFile(files []mw2PublisherFile, fileID uint64) (mw2PublisherFile, bool) {
	for _, file := range files {
		if file.id == fileID {
			return file, true
		}
	}
	return mw2PublisherFile{}, false
}

func (c *lsgConnection) handleStorageTask(payload []byte) (byte, []byte, bool) {
	c.lastServiceID = bdServiceStorage
	c.lastOperationID = 0
	c.lastStorageFiles = nil
	c.lastStorageFileIDs = nil
	c.lastStorageGetFile = ""
	c.lastStorageGetID = ""
	request, err := parseMW2StorageRequest(payload)
	if err != nil {
		return lsgTaskReplyType, c.storageErrorReply(0, bdErrorServiceNotAvailable), true
	}
	c.lastOperationID = request.operationID

	if c.userFiles == nil {
		c.userFiles = newMemoryMW2UserFileStore()
	}
	var reply []byte
	switch request.operationID {
	case bdStorageUploadUserFile:
		if request.filename != mw2ProfileFilename || len(request.data) != mw2ProfileSize {
			reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
			break
		}
		file, err := c.userFiles.upload(c.entityID, request.filename, request.data)
		if err != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
			break
		}
		c.lastTaskSupported = true
		reply = c.storageMutationReply(request.operationID, file.id)
	case bdStorageUpdateUserFile:
		if len(request.data) != mw2ProfileSize {
			reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
			break
		}
		file, ok, err := c.userFiles.update(c.entityID, request.fileID, request.data)
		if err != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
			break
		}
		if !ok {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		c.lastTaskSupported = true
		reply = c.storageMutationReply(request.operationID, file.id)
	case bdStorageListOwnerFiles:
		c.entityID = request.ownerID
		c.lastTaskSupported = true
		files, err := c.userFiles.list(request.ownerID)
		if err != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
			break
		}
		if request.offset >= uint32(len(files)) || request.maximum == 0 {
			files = nil
		} else {
			files = files[request.offset:]
			if len(files) > int(request.maximum) {
				files = files[:request.maximum]
			}
		}
		reply = c.storageOwnerListReply(files)
	case bdStorageListFiles:
		c.lastTaskSupported = true
		files, loadErr := loadMW2PublisherFiles()
		if loadErr != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		playlist := files[1]
		c.playlistBytes = len(playlist.data)
		c.playlistSHA256 = digestHex(playlist.data)
		selected := selectMW2PublisherFiles(files, request)
		for _, file := range selected {
			c.lastStorageFiles = append(c.lastStorageFiles, file.name)
			c.lastStorageFileIDs = append(c.lastStorageFileIDs, fmt.Sprintf("0x%016x", file.id))
		}
		reply = c.storagePublisherListReply(selected)
	case bdStorageGetFile:
		c.lastTaskSupported = true
		userFile, found, err := c.userFiles.get(request.fileID)
		if err != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
			break
		}
		if found {
			c.lastStorageGetFile = userFile.name
			c.lastStorageGetID = fmt.Sprintf("0x%016x", userFile.id)
			reply = c.storageUserGetReply(userFile)
			break
		}
		files, loadErr := loadMW2PublisherFiles()
		if loadErr != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		file, found := findMW2PublisherFile(files, request.fileID)
		if !found {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		c.lastStorageGetFile = file.name
		c.lastStorageGetID = fmt.Sprintf("0x%016x", file.id)
		if file.id == mw2PlaylistFileID || file.id == mw2PlaylistPatch3FileID {
			c.playlistBytes = len(file.data)
			c.playlistSHA256 = digestHex(file.data)
		}
		reply = c.storagePublisherGetReply(file)
	default:
		reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
	}
	return lsgTaskReplyType, reply, true
}
