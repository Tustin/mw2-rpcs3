package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/josh/mw2-rpcs3/internal/auth"
)

type ServerBackend interface {
	AdminProfiles(ctx context.Context, limit, offset int) ([]auth.AdminProfile, error)
	AdminLeaderboard(ctx context.Context, boardID int32, limit, offset int) ([]auth.AdminLeaderboardRow, error)
}

type Stats func() map[string]uint64

type Server struct {
	backend      ServerBackend
	stats        Stats
	playlistPath string
	started      time.Time
	assets       fs.FS
}

func NewServer(backend ServerBackend, stats Stats, playlistPath string, assets fs.FS) *Server {
	return &Server{backend: backend, stats: stats, playlistPath: playlistPath, started: time.Now(), assets: assets}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/api/v1/status", s.status)
	mux.HandleFunc("GET /admin/api/v1/profiles", s.profiles)
	mux.HandleFunc("GET /admin/api/v1/leaderboards", s.leaderboards)
	mux.HandleFunc("GET /admin/api/v1/playlist", s.playlist)
	mux.Handle("/admin/", s.spa())
	mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/", http.StatusTemporaryRedirect)
	})
	return mux
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "uptimeSeconds": uint64(time.Since(s.started).Seconds()), "metrics": s.stats()})
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

func (s *Server) playlist(w http.ResponseWriter, _ *http.Request) {
	data, err := os.ReadFile(s.playlistPath)
	if err != nil {
		writeError(w, err)
		return
	}
	sum := sha256.Sum256(data)
	writeJSON(w, http.StatusOK, map[string]any{"filename": "playlists.info", "size": len(data), "sha256": hex.EncodeToString(sum[:])})
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
