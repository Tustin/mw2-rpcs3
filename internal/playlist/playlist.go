package playlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"
)

const MaxSize = 0x20000

func Read(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := Validate(data); err != nil {
		return nil, fmt.Errorf("playlist file %q: %w", path, err)
	}
	return data, nil
}

func Validate(data []byte) error {
	if len(data) == 0 {
		return errors.New("playlist is empty")
	}
	if len(data) > MaxSize {
		return fmt.Errorf("playlist is %d bytes, maximum is %d", len(data), MaxSize)
	}
	if !utf8.Valid(data) {
		return errors.New("playlist is not valid UTF-8")
	}
	for _, value := range data {
		if value == 0 {
			return errors.New("playlist contains a NUL byte")
		}
	}
	return nil
}

func WriteAtomic(path string, data []byte) error {
	if err := Validate(data); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".playlists.info-*")
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
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
