package ezpatch

import (
	"encoding/binary"
	"net/http"
	"strings"
)

const (
	FormatVersion = 269
	IndexSize     = 0xB14
	TestVersion   = 1
)

func TestCBO() []byte {
	data := make([]byte, IndexSize)
	binary.BigEndian.PutUint32(data[0x00:0x04], FormatVersion)
	binary.BigEndian.PutUint64(data[0x04:0x0C], 0)
	binary.BigEndian.PutUint32(data[0x0C:0x10], TestVersion)
	binary.BigEndian.PutUint32(data[0x10:0x14], 0)
	return data
}

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ez_patch/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/ez_patch/")
		switch {
		case strings.HasSuffix(name, "_version.txt"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte("1"))
		case strings.HasSuffix(name, ".cbo"):
			data := TestCBO()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", "2836")
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}
