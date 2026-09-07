package auth

import (
	"context"
	"encoding/binary"
	"fmt"
)

type AdminProfile struct {
	OwnerID  uint64 `json:"ownerId"`
	FileID   uint64 `json:"fileId"`
	Filename string `json:"filename"`
	Size     int    `json:"size"`
}

type AdminLeaderboardRow struct {
	BoardID  int32   `json:"boardId"`
	EntityID uint64  `json:"entityId"`
	Rating   int64   `json:"rating"`
	Rank     uint64  `json:"rank"`
	Name     string  `json:"name"`
	Columns  []int32 `json:"columns"`
}

func (s *RawServer) AdminProfiles(ctx context.Context, limit, offset int) ([]AdminProfile, error) {
	if s.userFiles == nil || s.userFiles.db == nil {
		return nil, nil
	}
	rows, err := s.userFiles.db.QueryContext(ctx, `SELECT id, owner_id, filename, length(data)
		FROM user_files ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list admin profiles: %w", err)
	}
	defer rows.Close()
	profiles := make([]AdminProfile, 0)
	for rows.Next() {
		var profile AdminProfile
		var owner []byte
		if err := rows.Scan(&profile.FileID, &owner, &profile.Filename, &profile.Size); err != nil {
			return nil, fmt.Errorf("scan admin profile: %w", err)
		}
		if len(owner) != 8 {
			return nil, fmt.Errorf("invalid profile owner size %d", len(owner))
		}
		profile.OwnerID = binary.BigEndian.Uint64(owner)
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin profiles: %w", err)
	}
	return profiles, nil
}

func (s *RawServer) AdminLeaderboard(ctx context.Context, boardID int32, limit, offset int) ([]AdminLeaderboardRow, error) {
	if s.stats == nil || s.stats.db == nil {
		return nil, nil
	}
	rows, err := s.stats.db.QueryContext(ctx, `SELECT entity_id, rating, entity_name, columns_blob
		FROM stats_rows WHERE board_id = ? ORDER BY rating DESC, entity_id ASC LIMIT ? OFFSET ?`, boardID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list admin leaderboard: %w", err)
	}
	defer rows.Close()
	result := make([]AdminLeaderboardRow, 0)
	for index := 0; rows.Next(); index++ {
		var row AdminLeaderboardRow
		var entity, columnsBlob []byte
		if err := rows.Scan(&entity, &row.Rating, &row.Name, &columnsBlob); err != nil {
			return nil, fmt.Errorf("scan admin leaderboard: %w", err)
		}
		if len(entity) != 8 {
			return nil, fmt.Errorf("invalid leaderboard entity size %d", len(entity))
		}
		columns, err := decodeStatsColumns(columnsBlob)
		if err != nil {
			return nil, err
		}
		row.BoardID = boardID
		row.EntityID = binary.BigEndian.Uint64(entity)
		row.Rank = uint64(offset + index + 1)
		row.Columns = append([]int32(nil), columns[:]...)
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin leaderboard: %w", err)
	}
	return result, nil
}
