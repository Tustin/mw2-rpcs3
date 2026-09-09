package playlist

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{name: "valid", data: []byte("version 1\n"), ok: true},
		{name: "empty", data: nil},
		{name: "invalid UTF-8", data: []byte{0xff}},
		{name: "NUL", data: []byte{'a', 0}},
		{name: "oversized", data: bytes.Repeat([]byte{'a'}, MaxSize+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := Validate(test.data)
			if (err == nil) != test.ok {
				t.Fatalf("Validate() error = %v, want success %v", err, test.ok)
			}
		})
	}
}

func TestWriteAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "playlists.info")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, []byte("new\n")); err != nil {
		t.Fatal(err)
	}
	data, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new\n" {
		t.Fatalf("data = %q, want %q", data, "new\n")
	}
}

func TestWriteAtomicRejectsInvalidContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "playlists.info")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteAtomic(path, nil); err == nil {
		t.Fatal("WriteAtomic accepted empty content")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "old" {
		t.Fatalf("data = %q, want original content", data)
	}
}
