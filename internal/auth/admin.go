package auth

import (
	"context"
	"database/sql"
	"encoding/binary"
	"fmt"
	"strconv"
)

type AdminProfile struct {
	OwnerID  string `json:"ownerId"`
	FileID   string `json:"fileId"`
	Filename string `json:"filename"`
	Size     int    `json:"size"`
	Data     []byte `json:"-"`
}

type AdminLeaderboardRow struct {
	BoardID  int32   `json:"boardId"`
	EntityID uint64  `json:"entityId"`
	Rating   int64   `json:"rating"`
	Rank     uint64  `json:"rank"`
	Name     string  `json:"name"`
	Columns  []int32 `json:"columns"`
}

func adminProfile(file mw2UserFile) AdminProfile {
	return AdminProfile{
		OwnerID:  strconv.FormatUint(file.ownerID, 10),
		FileID:   strconv.FormatUint(file.id, 10),
		Filename: file.name,
		Size:     len(file.data),
		Data:     append([]byte(nil), file.data...),
	}
}

func (s *RawServer) AdminProfiles(ctx context.Context, limit, offset int) ([]AdminProfile, error) {
	if s.userFiles == nil || s.userFiles.db == nil {
		return nil, nil
	}
	rows, err := s.userFiles.db.QueryContext(ctx, `SELECT id, owner_id, filename, data
		FROM user_files ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list admin profiles: %w", err)
	}
	defer rows.Close()
	profiles := make([]AdminProfile, 0)
	for rows.Next() {
		file, err := scanMW2UserFile(rows)
		if err != nil {
			return nil, fmt.Errorf("scan admin profile: %w", err)
		}
		profile := adminProfile(file)
		profile.Data = nil
		profiles = append(profiles, profile)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin profiles: %w", err)
	}
	return profiles, nil
}

func (s *RawServer) AdminProfile(ctx context.Context, fileID uint64) (AdminProfile, bool, error) {
	if s.userFiles == nil || s.userFiles.db == nil {
		return AdminProfile{}, false, nil
	}
	file, err := scanMW2UserFile(s.userFiles.db.QueryRowContext(ctx, `SELECT id, owner_id, filename, data FROM user_files WHERE id = ?`, fileID))
	if err != nil {
		if err == sql.ErrNoRows {
			return AdminProfile{}, false, nil
		}
		return AdminProfile{}, false, fmt.Errorf("get admin profile: %w", err)
	}
	return adminProfile(file), true, nil
}

func (s *RawServer) AdminUpdateProfile(ctx context.Context, fileID uint64, data []byte) (AdminProfile, bool, error) {
	if s.userFiles == nil || s.userFiles.db == nil {
		return AdminProfile{}, false, nil
	}
	if len(data) != mw2ProfileSize {
		return AdminProfile{}, false, fmt.Errorf("profile is %d bytes, expected %d", len(data), mw2ProfileSize)
	}
	result, err := s.userFiles.db.ExecContext(ctx, `UPDATE user_files SET data = ? WHERE id = ?`, data, fileID)
	if err != nil {
		return AdminProfile{}, false, fmt.Errorf("update admin profile: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return AdminProfile{}, false, fmt.Errorf("read updated admin profile count: %w", err)
	}
	if rows == 0 {
		return AdminProfile{}, false, nil
	}
	return s.AdminProfile(ctx, fileID)
}

func (s *RawServer) AdminDeleteProfile(ctx context.Context, fileID uint64) (bool, error) {
	if s.userFiles == nil || s.userFiles.db == nil {
		return false, nil
	}
	result, err := s.userFiles.db.ExecContext(ctx, `DELETE FROM user_files WHERE id = ?`, fileID)
	if err != nil {
		return false, fmt.Errorf("delete admin profile: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read deleted admin profile count: %w", err)
	}
	return rows != 0, nil
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
