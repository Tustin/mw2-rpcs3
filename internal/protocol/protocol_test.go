package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := Frame{Kind: KindRequest, Service: 7, Task: 9, Flags: 1, Transaction: 42, Payload: []byte("hello")}
	var buf bytes.Buffer
	if err := WriteFrame(&buf, want, 1024); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != want.Kind || got.Service != want.Service || got.Task != want.Task || got.Transaction != want.Transaction || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestFrameLimit(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Frame{Kind: KindRequest, Payload: make([]byte, 10)}, 9); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v", err)
	}
}

func TestTypedBufferRoundTrip(t *testing.T) {
	var enc Encoder
	enc.Uint32(12)
	enc.String("player")
	enc.Bool(true)
	dec := NewDecoder(enc.Data(), 100)
	id, _ := dec.Uint32()
	name, _ := dec.String()
	online, _ := dec.Bool()
	if id != 12 || name != "player" || !online || dec.Remaining() != 0 {
		t.Fatal("typed buffer mismatch")
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = ReadFrame(bytes.NewReader(data), 4096) })
}
