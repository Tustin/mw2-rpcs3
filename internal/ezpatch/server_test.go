package ezpatch

import (
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestTestCBO(t *testing.T) {
	payload := make([]byte, 0x18)
	copy(payload, []byte("IWffu100"))
	binary.BigEndian.PutUint32(payload[0x08:0x0C], FormatVersion)
	binary.BigEndian.PutUint64(payload[0x0D:0x15], 0x01DD3FF2A0ACB1FC)
	copy(payload[0x15:], []byte{0x11, 0x22, 0x33})
	data := TestCBO(payload)
	if len(data) != IndexSize+len(payload) {
		t.Fatalf("len = %d, want %d", len(data), IndexSize+len(payload))
	}
	if got := binary.BigEndian.Uint32(data[0x00:0x04]); got != FormatVersion {
		t.Fatalf("format version = %d, want %d", got, FormatVersion)
	}
	if got := binary.BigEndian.Uint64(data[0x04:0x0C]); got != 0x01DD3FF2A0ACB1FC {
		t.Fatalf("content version = %#x, want %#x", got, uint64(0x01DD3FF2A0ACB1FC))
	}
	if got := binary.BigEndian.Uint32(data[0x0C:0x10]); got != TestVersion {
		t.Fatalf("patch version = %d, want %d", got, TestVersion)
	}
	if got := binary.BigEndian.Uint32(data[0x10:0x14]); got != 1 {
		t.Fatalf("entry count = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint32(data[0x14:0x18]); got != IndexSize {
		t.Fatalf("base offset = %#x, want %#x", got, IndexSize)
	}
	if got := string(data[0x18 : 0x18+len(TestFilename)]); got != TestFilename {
		t.Fatalf("filename = %q, want %q", got, TestFilename)
	}
	if got := data[IndexSize:]; string(got) != string(payload) {
		t.Fatalf("payload = %x, want %x", got, payload)
	}
}

func TestHandler(t *testing.T) {
	payload := []byte{0x11, 0x22, 0x33}
	path := t.TempDir() + "/payload.ff"
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MW2_EZPATCH_PAYLOAD_FILE", path)
	tests := []struct {
		path        string
		status      int
		contentType string
		bodyLength  int
		body        string
	}{
		{"/ez_patch/unknown_version.txt", http.StatusOK, "text/plain", 4, "1003"},
		{"/ez_patch/unknown.cbo", http.StatusOK, "application/octet-stream", IndexSize + len(payload), ""},
		{"/ez_patch/unknown", http.StatusNotFound, "text/plain; charset=utf-8", 19, "404 page not found\n"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			result := response.Result()
			defer result.Body.Close()
			body, err := io.ReadAll(result.Body)
			if err != nil {
				t.Fatal(err)
			}
			if result.StatusCode != test.status || result.Header.Get("Content-Type") != test.contentType || len(body) != test.bodyLength {
				t.Fatalf("status=%d content-type=%q len=%d", result.StatusCode, result.Header.Get("Content-Type"), len(body))
			}
			if test.body != "" && string(body) != test.body {
				t.Fatalf("body = %q, want %q", body, test.body)
			}
		})
	}
}
