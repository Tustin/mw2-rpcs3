package admin

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"encoding/binary"

	"github.com/josh/mw2-rpcs3/internal/auth"
	"github.com/josh/mw2-rpcs3/internal/ezpatch"
	"github.com/josh/mw2-rpcs3/internal/playlist"
)

type testBackend struct{}

func (testBackend) AdminProfiles(context.Context, int, int) ([]auth.AdminProfile, error) {
	return []auth.AdminProfile{{OwnerID: "11", FileID: "22", Filename: "mpdata", Size: 8192}}, nil
}

func (testBackend) AdminProfile(_ context.Context, fileID uint64) (auth.AdminProfile, bool, error) {
	if fileID != 22 {
		return auth.AdminProfile{}, false, nil
	}
	return auth.AdminProfile{OwnerID: "11", FileID: "22", Filename: "iw4-mpdata", Size: 8192, Data: bytes.Repeat([]byte{0x5a}, 8192)}, true, nil
}

func (testBackend) AdminUpdateProfile(_ context.Context, fileID uint64, data []byte) (auth.AdminProfile, bool, error) {
	if fileID != 22 {
		return auth.AdminProfile{}, false, nil
	}
	return auth.AdminProfile{OwnerID: "11", FileID: "22", Filename: "iw4-mpdata", Size: len(data), Data: append([]byte(nil), data...)}, true, nil
}

func (testBackend) AdminDeleteProfile(_ context.Context, fileID uint64) (bool, error) {
	return fileID == 22, nil
}

func (testBackend) AdminLeaderboard(context.Context, int32, int, int) ([]auth.AdminLeaderboardRow, error) {
	return []auth.AdminLeaderboardRow{{BoardID: 1, EntityID: 44, Rating: 55, Rank: 1, Name: "player", Columns: []int32{66}}}, nil
}

func (testBackend) Population() auth.PopulationSnapshot {
	return auth.PopulationSnapshot{OnlinePlayers: 2, AdvertisedPlayers: 3, Sessions: 1}
}

func TestServerAPI(t *testing.T) {
	handler, _ := testHandler(t)
	tests := []struct {
		path string
		body string
	}{
		{"/admin/api/v1/status", `"requests":7`},
		{"/admin/api/v1/population", `"onlinePlayers":2`},
		{"/admin/api/v1/profiles", `"fileId":"22"`},
		{"/admin/api/v1/profiles/22", `"ownerId":"11"`},
		{"/admin/api/v1/leaderboards?boardId=1", `"name":"player"`},
		{"/admin/api/v1/playlist", `"content":"playlist\n"`},
		{"/admin/api/v1/ezpatch", `"filename":"ez_common_mp.ff"`},
		{"/admin/unknown/route", "admin ui"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := serve(handler, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
			if body := response.Body.String(); !strings.Contains(body, test.body) {
				t.Fatalf("body = %q, want substring %q", body, test.body)
			}
		})
	}
}

func TestServerDownloadsProfile(t *testing.T) {
	handler, _ := testHandler(t)
	response := serve(handler, httptest.NewRequest(http.MethodGet, "/admin/api/v1/profiles/22/download", nil))
	if response.Code != http.StatusOK || response.Body.Len() != 8192 {
		t.Fatalf("status = %d, size = %d", response.Code, response.Body.Len())
	}
	if response.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content type = %q", response.Header().Get("Content-Type"))
	}
}

func TestServerUpdatesProfile(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/profiles/22", bytes.NewReader(bytes.Repeat([]byte{0x31}, 8192)))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := serve(handler, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"size":8192`) {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerRejectsWrongProfileSize(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/profiles/22", strings.NewReader("short"))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := serve(handler, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerDeletesProfile(t *testing.T) {
	handler, _ := testHandler(t)
	response := serve(handler, httptest.NewRequest(http.MethodDelete, "/admin/api/v1/profiles/22", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerProfileNotFound(t *testing.T) {
	handler, _ := testHandler(t)
	response := serve(handler, httptest.NewRequest(http.MethodGet, "/admin/api/v1/profiles/23", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerUpdatesPlaylist(t *testing.T) {
	handler, playlistPath := testHandler(t)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/playlist", strings.NewReader("updated playlist\n"))
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	response := serve(handler, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	data, err := os.ReadFile(playlistPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "updated playlist\n" {
		t.Fatalf("playlist = %q", data)
	}
}

func TestServerUpdatesEZPatch(t *testing.T) {
	handler, _ := testHandler(t)
	payload := make([]byte, 0x19)
	copy(payload, []byte("IWffu100"))
	binary.BigEndian.PutUint32(payload[0x08:0x0C], ezpatch.FormatVersion)
	binary.BigEndian.PutUint64(payload[0x0D:0x15], 0x01DD3FF2A0ACB1FD)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/ezpatch", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := serve(handler, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":1005`) {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerOverridesEZPatchVersion(t *testing.T) {
	handler, _ := testHandler(t)
	payload := make([]byte, 0x19)
	copy(payload, []byte("IWffu100"))
	binary.BigEndian.PutUint32(payload[0x08:0x0C], ezpatch.FormatVersion)
	binary.BigEndian.PutUint64(payload[0x0D:0x15], 0x01DD3FF2A0ACB1FD)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/ezpatch?version=2000", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := serve(handler, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"version":2000`) {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerRejectsInvalidEZPatch(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/ezpatch", strings.NewReader("invalid"))
	request.Header.Set("Content-Type", "application/octet-stream")
	response := serve(handler, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerRejectsInvalidPlaylist(t *testing.T) {
	handler, playlistPath := testHandler(t)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/playlist", bytes.NewReader([]byte{'a', 0}))
	request.Header.Set("Content-Type", "text/plain")
	response := serve(handler, request)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	data, err := os.ReadFile(playlistPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "playlist\n" {
		t.Fatalf("playlist changed to %q", data)
	}
}

func TestServerRejectsOversizedPlaylist(t *testing.T) {
	handler, _ := testHandler(t)
	request := httptest.NewRequest(http.MethodPut, "/admin/api/v1/playlist", bytes.NewReader(bytes.Repeat([]byte{'a'}, playlist.MaxSize+1)))
	request.Header.Set("Content-Type", "text/plain")
	response := serve(handler, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
}

func TestServerRequiresBoardID(t *testing.T) {
	handler, _ := testHandler(t)
	response := serve(handler, httptest.NewRequest(http.MethodGet, "/admin/api/v1/leaderboards", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func testHandler(t *testing.T) (http.Handler, string) {
	t.Helper()
	playlistPath := filepath.Join(t.TempDir(), "playlists.info")
	if err := os.WriteFile(playlistPath, []byte("playlist\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ezPatchRoot := filepath.Join(t.TempDir(), "ezpatch")
	seedPath := filepath.Join(t.TempDir(), "seed.ff")
	payload := make([]byte, 0x18)
	copy(payload, []byte("IWffu100"))
	binary.BigEndian.PutUint32(payload[0x08:0x0C], ezpatch.FormatVersion)
	binary.BigEndian.PutUint64(payload[0x0D:0x15], 0x01DD3FF2A0ACB1FC)
	if err := os.WriteFile(seedPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	ezPatch, err := ezpatch.OpenStore(ezPatchRoot, seedPath)
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("admin ui")}}
	return NewServer(testBackend{}, func() map[string]uint64 { return map[string]uint64{"requests": 7} }, playlistPath, ezPatch, assets).Handler(), playlistPath
}

func serve(handler http.Handler, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
