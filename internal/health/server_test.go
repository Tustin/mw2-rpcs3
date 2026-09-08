package health

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerRouting(t *testing.T) {
	ezPatch := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ezpatch"))
	})
	extra := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("extra"))
	})
	handler := newHandler(func() map[string]uint64 { return map[string]uint64{"requests": 1} }, ezPatch, extra)

	tests := []struct {
		path string
		body string
	}{
		{"/healthz", `{"status":"ok"}`},
		{"/ez_patch/test.cbo", "ezpatch"},
		{"/other", "extra"},
	}
	for _, test := range tests {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
		body, err := io.ReadAll(response.Result().Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != test.body {
			t.Fatalf("%s body = %q, want %q", test.path, body, test.body)
		}
	}
}

func TestServeWithHandlersCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ServeWithHandlers(ctx, "127.0.0.1:0", func() map[string]uint64 { return nil }, nil, nil); err != nil {
		t.Fatal(err)
	}
}
