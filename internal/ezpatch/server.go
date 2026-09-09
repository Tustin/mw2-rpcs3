package ezpatch

import (
	"encoding/binary"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const (
	FormatVersion = 269
	IndexSize     = 0xB14
	TestVersion   = 1003
	TestFilename  = "ez_common_mp"
)

func TestCBO(payload []byte) []byte {
	data := make([]byte, IndexSize+len(payload))
	binary.BigEndian.PutUint32(data[0x00:0x04], FormatVersion)
	if len(payload) >= 0x15 {
		copy(data[0x04:0x0C], payload[0x0D:0x15])
	}
	binary.BigEndian.PutUint32(data[0x0C:0x10], TestVersion)
	binary.BigEndian.PutUint32(data[0x10:0x14], 1)
	binary.BigEndian.PutUint32(data[0x14:0x18], IndexSize)
	copy(data[0x18:0x40], TestFilename)
	copy(data[IndexSize:], payload)
	return data
}

func payloadPath() string {
	if path := os.Getenv("MW2_EZPATCH_PAYLOAD_FILE"); path != "" {
		return path
	}
	return "ezpatch/test/ez_common_mp.ff"
}

func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ez_patch/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/ez_patch/")
		switch {
		case strings.HasSuffix(name, "_version.txt"):
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(strconv.Itoa(TestVersion)))
		case strings.HasSuffix(name, ".cbo"):
			payload, err := os.ReadFile(payloadPath())
			if err != nil {
				http.Error(w, "EZ Patch payload unavailable", http.StatusInternalServerError)
				return
			}
			data := TestCBO(payload)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}
