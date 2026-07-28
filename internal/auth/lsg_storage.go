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

func (c *lsgConnection) storageListReply(data []byte) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageListFiles)
	writer.writeU32(1)
	writer.writeU32(uint32(len(data)))
	writeMW2FileInfo(writer)
	return writer.bytes()
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

func (c *lsgConnection) storageGetReply(data []byte) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(bdStorageGetFile)
	writer.writeU32(uint32(len(data)))
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
	c.lastServiceID = bdServiceStorage
	c.lastOperationID = 0
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
		if request.maximum == 0 || request.offset > 0 ||
			(request.filter != "" && request.filter != mw2PlaylistFilename) {
			reply = c.storageEmptyListReply()
			break
		}
		data, loadErr := loadMW2Playlist()
		if loadErr != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		c.playlistBytes = len(data)
		c.playlistSHA256 = digestHex(data)
		reply = c.storageListReply(data)
	case bdStorageGetFile:
		c.lastTaskSupported = true
		if request.fileID != mw2PlaylistFileID {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		data, loadErr := loadMW2Playlist()
		if loadErr != nil {
			reply = c.storageErrorReply(request.operationID, bdErrorNoFile)
			break
		}
		c.playlistBytes = len(data)
		c.playlistSHA256 = digestHex(data)
		reply = c.storageGetReply(data)
	default:
		reply = c.storageErrorReply(request.operationID, bdErrorServiceNotAvailable)
	}
	return lsgTaskReplyType, reply, true
}
