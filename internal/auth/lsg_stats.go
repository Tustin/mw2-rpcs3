package auth

import (
	"database/sql"
	"encoding/binary"
	"fmt"
	"sort"

	_ "modernc.org/sqlite"
)

const (
	bdStatsWrite        = byte(1)
	bdStatsReadByEntity = byte(4)
	mw2StatsColumnCount = 10
)

type mw2StatsWriteRequest struct {
	context   byte
	writeType byte
	boardID   int32
	entityID  uint64
	rating    int64
	columns   [mw2StatsColumnCount]int32
}

type mw2StatsReadRequest struct {
	context   byte
	boardID   int32
	entityIDs []uint64
}

type mw2StatsRow struct {
	boardID  int32
	entityID uint64
	rating   int64
	rank     uint64
	name     string
	columns  [mw2StatsColumnCount]int32
}

type mw2StatsStore struct {
	db *sql.DB
}

func newMW2StatsStore(path string) (*mw2StatsStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open stats database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS stats_rows (
		board_id INTEGER NOT NULL,
		entity_id BLOB NOT NULL,
		rating INTEGER NOT NULL,
		entity_name TEXT NOT NULL,
		columns_blob BLOB NOT NULL,
		PRIMARY KEY (board_id, entity_id)
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize stats database: %w", err)
	}
	return &mw2StatsStore{db: db}, nil
}

func (s *mw2StatsStore) close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func statsEntityKey(entityID uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, entityID)
	return key
}

func statsColumnsBlob(columns [mw2StatsColumnCount]int32) []byte {
	blob := make([]byte, mw2StatsColumnCount*4)
	for index, value := range columns {
		binary.LittleEndian.PutUint32(blob[index*4:], uint32(value))
	}
	return blob
}

func decodeStatsColumns(blob []byte) ([mw2StatsColumnCount]int32, error) {
	var columns [mw2StatsColumnCount]int32
	if len(blob) != len(columns)*4 {
		return columns, fmt.Errorf("invalid stats column size %d", len(blob))
	}
	for index := range columns {
		columns[index] = int32(binary.LittleEndian.Uint32(blob[index*4:]))
	}
	return columns, nil
}

func (s *mw2StatsStore) replace(row mw2StatsRow) error {
	_, err := s.db.Exec(`INSERT INTO stats_rows (board_id, entity_id, rating, entity_name, columns_blob)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(board_id, entity_id) DO UPDATE SET
			rating = excluded.rating,
			entity_name = excluded.entity_name,
			columns_blob = excluded.columns_blob`,
		row.boardID, statsEntityKey(row.entityID), row.rating, row.name, statsColumnsBlob(row.columns))
	if err != nil {
		return fmt.Errorf("replace stats row: %w", err)
	}
	return nil
}

func (s *mw2StatsStore) readByEntity(boardID int32, entityIDs []uint64) ([]mw2StatsRow, error) {
	rows := make([]mw2StatsRow, 0, len(entityIDs))
	for _, entityID := range entityIDs {
		var row mw2StatsRow
		var storedEntity []byte
		var columnsBlob []byte
		err := s.db.QueryRow(`SELECT entity_id, rating, entity_name, columns_blob
			FROM stats_rows WHERE board_id = ? AND entity_id = ?`, boardID, statsEntityKey(entityID)).Scan(
			&storedEntity, &row.rating, &row.name, &columnsBlob)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read stats row: %w", err)
		}
		if len(storedEntity) != 8 {
			return nil, fmt.Errorf("invalid stats entity size %d", len(storedEntity))
		}
		row.boardID = boardID
		row.entityID = binary.BigEndian.Uint64(storedEntity)
		row.columns, err = decodeStatsColumns(columnsBlob)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	if err := s.assignRanks(boardID, rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (s *mw2StatsStore) assignRanks(boardID int32, rows []mw2StatsRow) error {
	if len(rows) == 0 {
		return nil
	}
	result, err := s.db.Query(`SELECT entity_id FROM stats_rows
		WHERE board_id = ? ORDER BY rating DESC, entity_id ASC`, boardID)
	if err != nil {
		return fmt.Errorf("rank stats rows: %w", err)
	}
	defer result.Close()
	ranks := make(map[uint64]uint64)
	for rank := uint64(1); result.Next(); rank++ {
		var entity []byte
		if err := result.Scan(&entity); err != nil {
			return fmt.Errorf("scan stats rank: %w", err)
		}
		if len(entity) != 8 {
			return fmt.Errorf("invalid ranked entity size %d", len(entity))
		}
		ranks[binary.BigEndian.Uint64(entity)] = rank
	}
	if err := result.Err(); err != nil {
		return fmt.Errorf("iterate stats ranks: %w", err)
	}
	for index := range rows {
		rows[index].rank = ranks[rows[index].entityID]
	}
	sort.SliceStable(rows, func(left, right int) bool {
		return rows[left].rank < rows[right].rank
	})
	return nil
}

func parseMW2StatsWriteRequest(payload []byte) (mw2StatsWriteRequest, error) {
	reader := newBDBitReader(payload)
	var request mw2StatsWriteRequest
	if typeChecked, err := reader.bits.readBits(1); err != nil || typeChecked != 1 {
		return request, fmt.Errorf("missing type-checking marker")
	}
	operationID, err := reader.readU8()
	if err != nil || operationID != bdStatsWrite {
		return request, fmt.Errorf("invalid stats write operation")
	}
	if request.context, err = reader.readU8(); err != nil {
		return request, err
	}
	if request.writeType, err = reader.readU8(); err != nil {
		return request, err
	}
	if request.boardID, err = reader.readI32(); err != nil {
		return request, err
	}
	if request.entityID, err = reader.readU64(); err != nil {
		return request, err
	}
	if request.rating, err = reader.readI64(); err != nil {
		return request, err
	}
	for index := range request.columns {
		if request.columns[index], err = reader.readI32(); err != nil {
			return request, err
		}
	}
	if reader.bits.remainingBits() > 63 {
		return request, fmt.Errorf("unexpected stats write data")
	}
	return request, nil
}

func parseMW2StatsReadRequest(payload []byte) (mw2StatsReadRequest, error) {
	reader := newBDBitReader(payload)
	var request mw2StatsReadRequest
	if typeChecked, err := reader.bits.readBits(1); err != nil || typeChecked != 1 {
		return request, fmt.Errorf("missing type-checking marker")
	}
	operationID, err := reader.readU8()
	if err != nil || operationID != bdStatsReadByEntity {
		return request, fmt.Errorf("invalid stats read operation")
	}
	if request.context, err = reader.readU8(); err != nil {
		return request, err
	}
	if request.boardID, err = reader.readI32(); err != nil {
		return request, err
	}
	count, err := reader.readU32()
	if err != nil {
		return request, err
	}
	if count > 1024 {
		return request, fmt.Errorf("stats entity count %d exceeds limit", count)
	}
	request.entityIDs = make([]uint64, count)
	for index := range request.entityIDs {
		if request.entityIDs[index], err = reader.readU64(); err != nil {
			return request, err
		}
	}
	if reader.bits.remainingBits() > 63 {
		return request, fmt.Errorf("unexpected stats read data")
	}
	return request, nil
}

func (c *lsgConnection) statsStore() *mw2StatsStore {
	if c.stats == nil {
		store, err := newMW2StatsStore(":memory:")
		if err == nil {
			c.stats = store
		}
	}
	return c.stats
}

func (c *lsgConnection) statsReply(operationID byte, rows []mw2StatsRow) []byte {
	writer := newBDBitWriter()
	writer.writeU64(c.nextTransactionID())
	writer.writeU32(bdErrorNone)
	writer.writeU8(operationID)
	writer.writeU32(uint32(len(rows)))
	writer.writeU32(uint32(len(rows)))
	for _, row := range rows {
		writer.writeU64(row.entityID)
		writer.writeI64(row.rating)
		writer.writeU64(row.rank)
		writer.writeString(row.name)
		for _, column := range row.columns {
			writer.writeI32(column)
		}
	}
	return writer.bytes()
}

func (c *lsgConnection) handleStatsTask(payload []byte) (byte, []byte, bool) {
	c.lastServiceID = bdServiceStats
	operationID, valid := decodeLSGTaskOperation(payload)
	if !valid {
		return lsgTaskReplyType, c.taskReply(0, bdErrorServiceNotAvailable, nil), true
	}
	c.lastOperationID = operationID
	store := c.statsStore()
	if store == nil {
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
	}
	switch operationID {
	case bdStatsWrite:
		request, err := parseMW2StatsWriteRequest(payload)
		if err != nil || request.writeType != 0 {
			return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
		}
		if request.entityID == 0 {
			request.entityID = c.entityID
		}
		if request.entityID == 0 {
			return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
		}
		name := fmt.Sprintf("%016x", request.entityID)
		if request.entityID == c.entityID {
			name = legacyUsername
		}
		if err := store.replace(mw2StatsRow{
			boardID: request.boardID, entityID: request.entityID, rating: request.rating,
			name: name, columns: request.columns,
		}); err != nil {
			return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
		}
		c.lastTaskSupported = true
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorNone, nil), true
	case bdStatsReadByEntity:
		request, err := parseMW2StatsReadRequest(payload)
		if err != nil {
			return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
		}
		for index, entityID := range request.entityIDs {
			if entityID == 0 {
				request.entityIDs[index] = c.entityID
			}
		}
		rows, err := store.readByEntity(request.boardID, request.entityIDs)
		if err != nil {
			return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
		}
		c.lastTaskSupported = true
		return lsgTaskReplyType, c.statsReply(operationID, rows), true
	default:
		return lsgTaskReplyType, c.taskReply(operationID, bdErrorServiceNotAvailable, nil), true
	}
}
