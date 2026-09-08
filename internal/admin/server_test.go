package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/josh/mw2-rpcs3/internal/auth"
)

type testBackend struct{}

func (testBackend) AdminProfiles(context.Context, int, int) ([]auth.AdminProfile, error) {
	return []auth.AdminProfile{{OwnerID: 11, FileID: 22, Filename: "mpdata", Size: 33}}, nil
}

func (testBackend) AdminLeaderboard(context.Context, int32, int, int) ([]auth.AdminLeaderboardRow, error) {
	return []auth.AdminLeaderboardRow{{BoardID: 1, EntityID: 44, Rating: 55, Rank: 1, Name: "player", Columns: []int32{66}}}, nil
}

func (testBackend) Population() auth.PopulationSnapshot {
	return auth.PopulationSnapshot{OnlinePlayers: 2, AdvertisedPlayers: 3, Sessions: 1}
}

func TestServerAPI(t *testing.T) {
	playlistPath := filepath.Join(t.TempDir(), "playlists.info")
	if err := os.WriteFile(playlistPath, []byte("playlist"), 0o600); err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("admin ui")}}
	handler := NewServer(testBackend{}, func() map[string]uint64 { return map[string]uint64{"requests": 7} }, playlistPath, assets).Handler()
	tests := []struct {
		path string
		body string
	}{
		{"/admin/api/v1/status", `"requests":7`},
		{"/admin/api/v1/population", `"onlinePlayers":2`},
		{"/admin/api/v1/profiles", `"filename":"mpdata"`},
		{"/admin/api/v1/leaderboards?boardId=1", `"name":"player"`},
		{"/admin/api/v1/playlist", `"filename":"playlists.info"`},
		{"/admin/unknown/route", "admin ui"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
			if body := response.Body.String(); !contains(body, test.body) {
				t.Fatalf("body = %q, want substring %q", body, test.body)
			}
		})
	}
}

func TestServerRequiresBoardID(t *testing.T) {
	handler := NewServer(testBackend{}, func() map[string]uint64 { return nil }, "", fstest.MapFS{}).Handler()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/api/v1/leaderboards", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestLocalOnlyMiddleware(t *testing.T) {
	handler := LocalOnly(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for _, test := range []struct {
		remote string
		status int
	}{
		{"127.0.0.1:1234", http.StatusNoContent},
		{"[::1]:1234", http.StatusNoContent},
		{"192.0.2.1:1234", http.StatusForbidden},
	} {
		request := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		request.RemoteAddr = test.remote
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("remote %q status = %d, want %d", test.remote, response.Code, test.status)
		}
	}
}

func TestAccessMiddlewareRequiresAssertion(t *testing.T) {
	validator, err := NewAccessValidator("team.cloudflareaccess.com", "audience")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	validator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was called")
	})).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/admin/", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func contains(value, substring string) bool {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return true
		}
	}
	return false
}
