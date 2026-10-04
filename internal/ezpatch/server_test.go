package ezpatch

import (
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func testPayload() []byte {
	payload := make([]byte, 0x18)
	copy(payload, []byte("IWffu100"))
	binary.BigEndian.PutUint32(payload[0x08:0x0C], FormatVersion)
	binary.BigEndian.PutUint64(payload[0x0D:0x15], 0x01DD3FF2A0ACB1FC)
	copy(payload[0x15:], []byte{0x11, 0x22, 0x33})
	return payload
}

func TestBuildCBO(t *testing.T) {
	payload := testPayload()
	data := BuildCBO(payload, DefaultVersion)
	if len(data) != IndexSize+len(payload) {
		t.Fatalf("len = %d, want %d", len(data), IndexSize+len(payload))
	}
	if got := binary.BigEndian.Uint32(data[0x00:0x04]); got != FormatVersion {
		t.Fatalf("format version = %d, want %d", got, FormatVersion)
	}
	if got := binary.BigEndian.Uint64(data[0x04:0x0C]); got != 0x01DD3FF2A0ACB1FC {
		t.Fatalf("content version = %#x", got)
	}
	if got := binary.BigEndian.Uint32(data[0x0C:0x10]); got != DefaultVersion {
		t.Fatalf("patch version = %d, want %d", got, DefaultVersion)
	}
	if got := string(data[0x18 : 0x18+len(Filename)]); got != Filename {
		t.Fatalf("filename = %q, want %q", got, Filename)
	}
	if got := data[IndexSize:]; string(got) != string(payload) {
		t.Fatalf("payload = %x, want %x", got, payload)
	}
}

func TestStoreUpdateAndHandler(t *testing.T) {
	directory := t.TempDir()
	seed := filepath.Join(directory, "seed.ff")
	if err := os.WriteFile(seed, testPayload(), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(filepath.Join(directory, "data"), seed)
	if err != nil {
		t.Fatal(err)
	}
	updated := testPayload()
	updated = append(updated, 0x44)
	info, err := store.Update(updated, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != DefaultVersion+1 {
		t.Fatalf("version = %d, want %d", info.Version, DefaultVersion+1)
	}
	tests := []struct {
		path        string
		contentType string
		body        string
		bodyLength  int
	}{
		{"/ez_patch/unknown_version.txt", "text/plain", "1005", 4},
		{"/ez_patch/unknown.cbo", "application/octet-stream", "", IndexSize + len(updated)},
		{"/ez_patch/unknown", "text/plain; charset=utf-8", "404 page not found\n", 19},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		store.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		body, err := io.ReadAll(response.Result().Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.Header().Get("Content-Type") != test.contentType || len(body) != test.bodyLength {
			t.Fatalf("%s content-type=%q len=%d", test.path, response.Header().Get("Content-Type"), len(body))
		}
		if test.body != "" && string(body) != test.body {
			t.Fatalf("%s body = %q, want %q", test.path, body, test.body)
		}
	}
}

func TestValidatePayload(t *testing.T) {
	for name, payload := range map[string][]byte{"small": {}, "header": append([]byte("badfile!"), make([]byte, 20)...), "format": append([]byte(nil), testPayload()...)} {
		if name == "format" {
			binary.BigEndian.PutUint32(payload[0x08:0x0C], 1)
		}
		if err := ValidatePayload(payload); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}
