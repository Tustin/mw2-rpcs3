package auth

import (
	"fmt"
	"os"
)

const (
	mw2PlaylistFileID       = uint64(0x1122334455667788)
	mw2PlaylistFilename     = "playlists.info"
	mw2PlaylistMaxSize      = 0x20000
	bdStorageListOwnerFiles = byte(7)
	bdStorageListFiles      = byte(8)
	bdStorageGetFile        = byte(5)
)

type bdBitWriter struct {
	bits *lsbBitWriter
}

func newBDBitWriter() *bdBitWriter {
	return &bdBitWriter{bits: newLSBBitWriter(0)}
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

func (w *bdBitWriter) writeU32(value uint32) {
	w.writeType(bdTypeU32)
	w.bits.writeBits(uint64(value), 32)
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

func (r *bdBitReader) readU32() (uint32, error) {
	if err := r.readType(bdTypeU32); err != nil {
		return 0, err
	}
	value, err := r.bits.readBits(32)
	return uint32(value), err
}

func (r *bdBitReader) readU64() (uint64, error) {
	if err := r.readType(bdTypeU64); err != nil {
		return 0, err
	}
	return r.bits.readBits(64)
}

type mw2StorageRequest struct {
	operationID byte
	fileID      uint64
	ownerID     uint64
	offset      uint32
	maximum     uint16
}

type mw2StorageReplySummary struct {
	transactionID    uint64
	errorCode        uint32
	operationID      byte
	resultCount      uint32
	totalResultCount uint32
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
		if _, err := reader.readU8(); err != nil {
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
		if _, err := reader.readU8(); err != nil {
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
	case bdStorageGetFile:
		request.fileID, err = reader.readU64()
		if err != nil {
			return mw2StorageRequest{}, fmt.Errorf("read storage file ID: %w", err)
		}
	}
	return request, nil
}

func parseMW2StorageReplySummary(payload []byte) (mw2StorageReplySummary, error) {
	reader := newBDBitReader(payload)
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
		summary.resultCount, err = reader.readU32()
		if err != nil {
			return mw2StorageReplySummary{}, fmt.Errorf("read storage reply result count: %w", err)
		}
		summary.totalResultCount, err = reader.readU32()
		if err != nil {
			return mw2StorageReplySummary{}, fmt.Errorf("read storage reply total result count: %w", err)
		}
	}
	return summary, nil
}

func (c *lsgConnection) nextTransactionID() uint64 {
	value := c.nextTransaction
	c.nextTransaction++
	return value
}

func writeMW2FileInfo(writer *bdBitWriter) {
	writer.writeU64(mw2PlaylistFileID)
	writer.writeU32(0)
	writer.writeU32(0)
	writer.writeBool(false)
	writer.writeBool(false)
	writer.writeU64(0)
	writer.writeString(mw2PlaylistFilename)
}

func (c *lsgConnection) storageErrorReply(operationID byte, errorCode uint32) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(errorCode)
	writer.writeU8(operationID)
	return writer.bytes()
}

func (c *lsgConnection) storageListReply() []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageListFiles)
	writer.writeU32(1)
	writer.writeU32(1)
	writeMW2FileInfo(writer)
	return writer.bytes()
}

func (c *lsgConnection) storageOwnerListReply() []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageListOwnerFiles)
	writer.writeU32(0)
	writer.writeU32(0)
	return writer.bytes()
}

func (c *lsgConnection) storageGetReply(data []byte) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageGetFile)
	writer.writeU32(1)
	writer.writeU32(1)
	writeMW2FileInfo(writer)
	writer.writeBlob(data)
	return writer.bytes()
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

func (c *lsgConnection) handleStorageTask(payload []byte) (byte, []byte, bool) {
	request, err := parseMW2StorageRequest(payload)
	if err != nil {
		return lsgTaskReplyType, c.storageErrorReply(0, bdErrorServiceNotAvailable), true
	}
	c.lastServiceID = bdServiceStorage
	c.lastOperationID = request.operationID

	var reply []byte
	switch request.operationID {
	case bdStorageListOwnerFiles:
		reply = c.storageOwnerListReply()
	case bdStorageListFiles:
		if _, loadErr := loadMW2Playlist(); loadErr != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		reply = c.storageListReply()
	case bdStorageGetFile:
		if request.fileID != mw2PlaylistFileID {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		data, loadErr := loadMW2Playlist()
		if loadErr != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		reply = c.storageGetReply(data)
	default:
		reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
	}
	return lsgTaskReplyType, reply, true
}
