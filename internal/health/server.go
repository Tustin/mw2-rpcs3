package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type Stats func() map[string]uint64

func Serve(ctx context.Context, addr string, stats Stats) error {
	return ServeWithHandlers(ctx, addr, stats, nil, nil)
}

func ServeWithHandler(ctx context.Context, addr string, stats Stats, extra http.Handler) error {
	return ServeWithHandlers(ctx, addr, stats, nil, extra)
}

func ServeWithHandlers(ctx context.Context, addr string, stats Stats, ezPatch http.Handler, extra http.Handler) error {
	server := &http.Server{Addr: addr, Handler: newHandler(stats, ezPatch, extra), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	err := server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func newHandler(stats Stats, ezPatch http.Handler, extra http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(stats())
	})
	if ezPatch != nil {
		mux.Handle("/ez_patch/", ezPatch)
	}
	if extra != nil {
		mux.Handle("/", extra)
	}
	return mux
}
