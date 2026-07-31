package auth

import (
	"fmt"
	"os"
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
	bdStorageListOwnerFiles = byte(7)
	bdStorageListFiles      = byte(8)
	bdStorageGetFile        = byte(5)
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
}

type mw2StorageReplySummary struct {
	transactionID uint64
	errorCode     uint32
	operationID   byte
	resultCount   uint32
	fileSize      uint32
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

func (c *lsgConnection) storageOwnerListReply() []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageListOwnerFiles)
	writer.writeU32(0)
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

	var reply []byte
	switch request.operationID {
	case bdStorageListOwnerFiles:
		c.lastTaskSupported = true
		reply = c.storageOwnerListReply()
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
