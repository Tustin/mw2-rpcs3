package admin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/josh/mw2-rpcs3/internal/auth"
	"github.com/josh/mw2-rpcs3/internal/playlist"
)

type ServerBackend interface {
	AdminProfiles(ctx context.Context, limit, offset int) ([]auth.AdminProfile, error)
	AdminProfile(ctx context.Context, fileID uint64) (auth.AdminProfile, bool, error)
	AdminUpdateProfile(ctx context.Context, fileID uint64, data []byte) (auth.AdminProfile, bool, error)
	AdminDeleteProfile(ctx context.Context, fileID uint64) (bool, error)
	AdminLeaderboard(ctx context.Context, boardID int32, limit, offset int) ([]auth.AdminLeaderboardRow, error)
	Population() auth.PopulationSnapshot
}

type Stats func() map[string]uint64

type Server struct {
	backend      ServerBackend
	stats        Stats
	playlistPath string
	started      time.Time
	assets       fs.FS
	playlistMu   sync.Mutex
}

func NewServer(backend ServerBackend, stats Stats, playlistPath string, assets fs.FS) *Server {
	return &Server{backend: backend, stats: stats, playlistPath: playlistPath, started: time.Now(), assets: assets}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/api/v1/status", s.status)
	mux.HandleFunc("GET /admin/api/v1/population", s.population)
	mux.HandleFunc("GET /admin/api/v1/profiles", s.profiles)
	mux.HandleFunc("GET /admin/api/v1/profiles/{fileID}", s.getProfile)
	mux.HandleFunc("GET /admin/api/v1/profiles/{fileID}/download", s.downloadProfile)
	mux.HandleFunc("PUT /admin/api/v1/profiles/{fileID}", s.putProfile)
	mux.HandleFunc("DELETE /admin/api/v1/profiles/{fileID}", s.deleteProfile)
	mux.HandleFunc("GET /admin/api/v1/leaderboards", s.leaderboards)
	mux.HandleFunc("GET /admin/api/v1/playlist", s.getPlaylist)
	mux.HandleFunc("PUT /admin/api/v1/playlist", s.putPlaylist)
	mux.Handle("/admin/", s.spa())
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
	})
	return mux
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "uptimeSeconds": uint64(time.Since(s.started).Seconds()), "metrics": s.stats()})
}

func (s *Server) population(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.backend.Population())
}

func (s *Server) profiles(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	profiles, err := s.backend.AdminProfiles(r.Context(), limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profiles": profiles})
}

func (s *Server) getProfile(w http.ResponseWriter, r *http.Request) {
	profile, ok := s.profile(w, r)
	if !ok {
		return
	}
	writeProfile(w, profile)
}

func (s *Server) downloadProfile(w http.ResponseWriter, r *http.Request) {
	profile, ok := s.profile(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="iw4-mpdata"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(profile.Data)))
	_, _ = w.Write(profile.Data)
}

func (s *Server) putProfile(w http.ResponseWriter, r *http.Request) {
	fileID, ok := profileFileID(w, r)
	if !ok {
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/octet-stream" {
		http.Error(w, "Content-Type must be application/octet-stream", http.StatusUnsupportedMediaType)
		return
	}
	body := http.MaxBytesReader(w, r.Body, 8192)
	data, err := io.ReadAll(body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "profile exceeds 8192 bytes", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(data) != 8192 {
		http.Error(w, "profile must be exactly 8192 bytes", http.StatusUnprocessableEntity)
		return
	}
	profile, found, err := s.backend.AdminUpdateProfile(r.Context(), fileID, data)
	if err != nil {
		writeError(w, err)
		return
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	writeProfile(w, profile)
}

func (s *Server) deleteProfile(w http.ResponseWriter, r *http.Request) {
	fileID, ok := profileFileID(w, r)
	if !ok {
		return
	}
	deleted, err := s.backend.AdminDeleteProfile(r.Context(), fileID)
	if err != nil {
		writeError(w, err)
		return
	}
	if !deleted {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) profile(w http.ResponseWriter, r *http.Request) (auth.AdminProfile, bool) {
	fileID, ok := profileFileID(w, r)
	if !ok {
		return auth.AdminProfile{}, false
	}
	profile, found, err := s.backend.AdminProfile(r.Context(), fileID)
	if err != nil {
		writeError(w, err)
		return auth.AdminProfile{}, false
	}
	if !found {
		http.NotFound(w, r)
		return auth.AdminProfile{}, false
	}
	return profile, true
}

func profileFileID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	fileID, err := strconv.ParseUint(r.PathValue("fileID"), 10, 64)
	if err != nil || fileID == 0 {
		http.Error(w, "valid file ID is required", http.StatusBadRequest)
		return 0, false
	}
	return fileID, true
}

func writeProfile(w http.ResponseWriter, profile auth.AdminProfile) {
	sum := sha256.Sum256(profile.Data)
	writeJSON(w, http.StatusOK, map[string]any{"ownerId": profile.OwnerID, "fileId": profile.FileID, "filename": profile.Filename, "size": profile.Size, "sha256": hex.EncodeToString(sum[:]), "data": base64.StdEncoding.EncodeToString(profile.Data)})
}

func (s *Server) leaderboards(w http.ResponseWriter, r *http.Request) {
	limit, offset := pagination(r)
	boardID, err := strconv.ParseInt(r.URL.Query().Get("boardId"), 10, 32)
	if err != nil {
		http.Error(w, "valid boardId is required", http.StatusBadRequest)
		return
	}
	rows, err := s.backend.AdminLeaderboard(r.Context(), int32(boardID), limit, offset)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}

func (s *Server) getPlaylist(w http.ResponseWriter, _ *http.Request) {
	data, err := playlist.Read(s.playlistPath)
	if err != nil {
		writeError(w, err)
		return
	}
	writePlaylist(w, data)
}

func (s *Server) putPlaylist(w http.ResponseWriter, r *http.Request) {
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "text/plain" {
		http.Error(w, "Content-Type must be text/plain", http.StatusUnsupportedMediaType)
		return
	}
	body := http.MaxBytesReader(w, r.Body, playlist.MaxSize)
	data, err := io.ReadAll(body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "playlist exceeds maximum size", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := playlist.Validate(data); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.playlistMu.Lock()
	err = playlist.WriteAtomic(s.playlistPath, data)
	s.playlistMu.Unlock()
	if err != nil {
		writeError(w, err)
		return
	}
	writePlaylist(w, data)
}

func writePlaylist(w http.ResponseWriter, data []byte) {
	sum := sha256.Sum256(data)
	writeJSON(w, http.StatusOK, map[string]any{"filename": "playlists.info", "size": len(data), "sha256": hex.EncodeToString(sum[:]), "content": string(data)})
}

func (s *Server) spa() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/admin/")
		if path == "" {
			path = "index.html"
		}
		data, err := fs.ReadFile(s.assets, path)
		if err != nil {
			path = "index.html"
			data, err = fs.ReadFile(s.assets, path)
		}
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if contentType := mime.TypeByExtension(filepath.Ext(path)); contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write(data)
	})
}

func pagination(r *http.Request) (int, int) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit < 1 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}
