package ezpatch

import (
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTestCBO(t *testing.T) {
	data := TestCBO()
	if len(data) != IndexSize {
		t.Fatalf("len = %d, want %d", len(data), IndexSize)
	}
	if got := binary.BigEndian.Uint32(data[0x00:0x04]); got != FormatVersion {
		t.Fatalf("format version = %d, want %d", got, FormatVersion)
	}
	if got := binary.BigEndian.Uint64(data[0x04:0x0C]); got != 0 {
		t.Fatalf("content version = %d, want 0", got)
	}
	if got := binary.BigEndian.Uint32(data[0x0C:0x10]); got != TestVersion {
		t.Fatalf("patch version = %d, want %d", got, TestVersion)
	}
	if got := binary.BigEndian.Uint32(data[0x10:0x14]); got != 0 {
		t.Fatalf("entry count = %d, want 0", got)
	}
}

func TestHandler(t *testing.T) {
	tests := []struct {
		path        string
		status      int
		contentType string
		bodyLength  int
		body        string
	}{
		{"/ez_patch/unknown_version.txt", http.StatusOK, "text/plain", 1, "1"},
		{"/ez_patch/unknown.cbo", http.StatusOK, "application/octet-stream", IndexSize, ""},
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
