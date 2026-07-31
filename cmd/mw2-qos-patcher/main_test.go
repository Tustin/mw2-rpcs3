package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildWrapperUsesOpenedFileDescriptorForWriteAndClose(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}

	writeCallOffset := branchOffsetTo(t, wrapper, cellFsWriteVMA)
	if instruction := binary.BigEndian.Uint32(wrapper[writeCallOffset-16 : writeCallOffset-12]); instruction != 0x806100d4 {
		t.Fatalf("write descriptor load=%08x want=806100d4", instruction)
	}

	closeCallOffset := branchOffsetTo(t, wrapper, cellFsCloseVMA)
	if instruction := binary.BigEndian.Uint32(wrapper[closeCallOffset-4 : closeCallOffset]); instruction != 0x806100d4 {
		t.Fatalf("close descriptor load=%08x want=806100d4", instruction)
	}
}

func TestBuildWrapperCopiesQoSCountersAndPath(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wrapper, []byte("/dev_hdd0/tmp/mw2_qos.bin\x00")) {
		t.Fatal("wrapper is missing the telemetry path")
	}
	for _, instruction := range []uint32{
		0x81230010,
		0x912100c0,
		0x81230014,
		0x912100c4,
		0x81230018,
		0x912100c8,
		0x8123001c,
		0x912100cc,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
}

func branchOffsetTo(t *testing.T, code []byte, target uint64) int {
	t.Helper()
	for offset := 0; offset+4 <= len(code); offset += 4 {
		instruction := binary.BigEndian.Uint32(code[offset : offset+4])
		address := wrapperVMA + uint64(offset)
		resolved, err := branchTarget(address, instruction)
		if err == nil && resolved == target {
			return offset
		}
	}
	t.Fatalf("branch to 0x%x not found", target)
	return 0
}
