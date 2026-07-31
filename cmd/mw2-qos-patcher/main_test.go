package main

import (
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
