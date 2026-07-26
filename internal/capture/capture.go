package capture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var sensitive = regexp.MustCompile(`(?i)(ticket|token|password|secret|authorization)[=: ]+[^\x00\s,;]+`)

type Record struct {
	Timestamp time.Time `json:"timestamp"`
	Listener  string    `json:"listener"`
	Direction string    `json:"direction"`
	Remote    string    `json:"remote"`
	Length    int       `json:"length"`
	SHA256    string    `json:"sha256"`
	Payload   string    `json:"payload_hex,omitempty"`
}

type Recorder struct {
	enabled  bool
	dir      string
	maxBytes int
	mu       sync.Mutex
}

func New(enabled bool, dir string, maxBytes int) *Recorder {
	return &Recorder{enabled: enabled, dir: dir, maxBytes: maxBytes}
}

func (r *Recorder) Record(listener, direction, remote string, data []byte) error {
	if !r.enabled {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(r.dir, 0o700); err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	redacted := sensitive.ReplaceAll(data, []byte("$1=[REDACTED]"))
	if len(redacted) > r.maxBytes {
		redacted = redacted[:r.maxBytes]
	}
	record := Record{Timestamp: time.Now().UTC(), Listener: listener, Direction: direction, Remote: remote, Length: len(data), SHA256: hex.EncodeToString(digest[:]), Payload: hex.EncodeToString(redacted)}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := filepath.Join(r.dir, fmt.Sprintf("capture-%s.jsonl", time.Now().UTC().Format("20060102")))
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(encoded, '\n'))
	return err
}
