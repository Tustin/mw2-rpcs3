package ezpatch

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	FormatVersion  = 269
	IndexSize      = 0xB14
	DefaultVersion = 1004
	Filename       = "ez_common_mp.ff"
	MaxPayloadSize = 64 << 20
)

type State struct {
	Version     uint32 `json:"version"`
	PayloadFile string `json:"payloadFile"`
}

type Status struct {
	Filename       string `json:"filename"`
	Version        uint32 `json:"version"`
	Size           int    `json:"size"`
	SHA256         string `json:"sha256"`
	ContentVersion string `json:"contentVersion"`
	UpdatedAt      string `json:"updatedAt"`
}

type Store struct {
	directory string
	statePath string
	mu        sync.RWMutex
}

func OpenStore(directory, seedPath string) (*Store, error) {
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	store := &Store{directory: directory, statePath: filepath.Join(directory, "state.json")}
	if _, err := os.Stat(store.statePath); err == nil {
		if _, _, err := store.snapshot(); err != nil {
			return nil, err
		}
		return store, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	payload, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, fmt.Errorf("read EZ Patch seed: %w", err)
	}
	if err := ValidatePayload(payload); err != nil {
		return nil, fmt.Errorf("validate EZ Patch seed: %w", err)
	}
	if _, err := store.install(payload, DefaultVersion); err != nil {
		return nil, err
	}
	return store, nil
}

func ValidatePayload(payload []byte) error {
	if len(payload) < 0x15 {
		return errors.New("fastfile is too small")
	}
	if len(payload) > MaxPayloadSize {
		return fmt.Errorf("fastfile is %d bytes, maximum is %d", len(payload), MaxPayloadSize)
	}
	if string(payload[:8]) != "IWffu100" {
		return errors.New("fastfile header must be IWffu100")
	}
	if binary.BigEndian.Uint32(payload[0x08:0x0C]) != FormatVersion {
		return fmt.Errorf("fastfile format must be %d", FormatVersion)
	}
	if binary.BigEndian.Uint64(payload[0x0D:0x15]) == 0 {
		return errors.New("fastfile content version is zero")
	}
	return nil
}

func (s *Store) Status() (Status, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, payload, err := s.snapshot()
	if err != nil {
		return Status{}, err
	}
	return status(state, payload, filepath.Join(s.directory, state.PayloadFile))
}

func (s *Store) Payload() ([]byte, Status, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, payload, err := s.snapshot()
	if err != nil {
		return nil, Status{}, err
	}
	info, err := status(state, payload, filepath.Join(s.directory, state.PayloadFile))
	return payload, info, err
}

func (s *Store) Update(payload []byte, version *uint32) (Status, error) {
	if err := ValidatePayload(payload); err != nil {
		return Status{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state, _, err := s.snapshot()
	if err != nil {
		return Status{}, err
	}
	next := state.Version + 1
	if version != nil {
		next = *version
	}
	if next == 0 {
		return Status{}, errors.New("version must be greater than zero")
	}
	return s.install(payload, next)
}

func (s *Store) CBO() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, payload, err := s.snapshot()
	if err != nil {
		return nil, err
	}
	return BuildCBO(payload, state.Version), nil
}

func BuildCBO(payload []byte, version uint32) []byte {
	data := make([]byte, IndexSize+len(payload))
	binary.BigEndian.PutUint32(data[0x00:0x04], FormatVersion)
	copy(data[0x04:0x0C], payload[0x0D:0x15])
	binary.BigEndian.PutUint32(data[0x0C:0x10], version)
	binary.BigEndian.PutUint32(data[0x10:0x14], 1)
	binary.BigEndian.PutUint32(data[0x14:0x18], IndexSize)
	copy(data[0x18:0x40], Filename)
	copy(data[IndexSize:], payload)
	return data
}

func (s *Store) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ez_patch/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/ez_patch/")
		switch {
		case strings.HasSuffix(name, "_version.txt"):
			info, err := s.Status()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(strconv.FormatUint(uint64(info.Version), 10)))
		case strings.HasSuffix(name, ".cbo"):
			data, err := s.CBO()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			_, _ = w.Write(data)
		default:
			http.NotFound(w, r)
		}
	})
	return mux
}

func (s *Store) snapshot() (State, []byte, error) {
	data, err := os.ReadFile(s.statePath)
	if err != nil {
		return State{}, nil, err
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, nil, err
	}
	if state.Version == 0 || filepath.Base(state.PayloadFile) != state.PayloadFile {
		return State{}, nil, errors.New("invalid EZ Patch state")
	}
	payload, err := os.ReadFile(filepath.Join(s.directory, state.PayloadFile))
	if err != nil {
		return State{}, nil, err
	}
	if err := ValidatePayload(payload); err != nil {
		return State{}, nil, err
	}
	return state, payload, nil
}

func (s *Store) install(payload []byte, version uint32) (Status, error) {
	sum := sha256.Sum256(payload)
	payloadFile := "payload-" + hex.EncodeToString(sum[:]) + ".ff"
	payloadPath := filepath.Join(s.directory, payloadFile)
	if _, err := os.Stat(payloadPath); errors.Is(err, os.ErrNotExist) {
		if err := writeAtomic(payloadPath, payload, 0o644); err != nil {
			return Status{}, err
		}
	} else if err != nil {
		return Status{}, err
	}
	state := State{Version: version, PayloadFile: payloadFile}
	data, err := json.Marshal(state)
	if err != nil {
		return Status{}, err
	}
	if err := writeAtomic(s.statePath, append(data, '\n'), 0o644); err != nil {
		return Status{}, err
	}
	return status(state, payload, payloadPath)
}

func status(state State, payload []byte, path string) (Status, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return Status{}, err
	}
	sum := sha256.Sum256(payload)
	return Status{Filename: Filename, Version: state.Version, Size: len(payload), SHA256: hex.EncodeToString(sum[:]), ContentVersion: fmt.Sprintf("0x%016X", binary.BigEndian.Uint64(payload[0x0D:0x15])), UpdatedAt: fileInfo.ModTime().UTC().Format(time.RFC3339)}, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".ezpatch-*")
	if err != nil {
		return err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func ReadUpload(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body := http.MaxBytesReader(w, r.Body, MaxPayloadSize)
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	return data, nil
}
