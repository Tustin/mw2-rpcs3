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
	if instruction := binary.BigEndian.Uint32(wrapper[writeCallOffset-28 : writeCallOffset-24]); instruction != 0x806103f0 {
		t.Fatalf("write descriptor load=%08x want=806103f0", instruction)
	}

	closeCallOffset := branchOffsetTo(t, wrapper, cellFsCloseVMA)
	if instruction := binary.BigEndian.Uint32(wrapper[closeCallOffset-4 : closeCallOffset]); instruction != 0x806103f0 {
		t.Fatalf("close descriptor load=%08x want=806103f0", instruction)
	}
}

func TestBuildWrapperCapturesOuterStateAndCFFPhases(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapper) > int(wrapperLimitVMA-wrapperVMA) {
		t.Fatalf("wrapper size=%d exceeds cave size=%d", len(wrapper), wrapperLimitVMA-wrapperVMA)
	}
	if !bytes.HasSuffix(wrapper, []byte("/dev_hdd0/tmp/mw2_qos.bin\x00")) {
		t.Fatal("wrapper is missing the telemetry path suffix")
	}
	for _, instruction := range []uint32{
		0x38000002,
		0xb00c0004,
		0x800b05b0,
		0x900c0018,
		0x800b0e4c,
		0x900c001c,
		0x800b0e50,
		0x900c0020,
		0x80152110,
		0x80152114,
		0x80152118,
		0x8015211c,
		0x80f52120,
		0x8807000c,
		0x80ea0038,
		0x80ca003c,
		0x81080044,
		0x38a00060,
		0x38a000c0,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
	branchOffsetToAny(t, wrapper, clearQoSCalleeVMA)
	for _, target := range []uint64{cffCalleeVMA, cellFsOpenVMA, cellFsWriteVMA, cellFsCloseVMA} {
		branchOffsetTo(t, wrapper, target)
	}
	for offset := 0; offset+4 <= len(wrapper)-len("/dev_hdd0/tmp/mw2_qos.bin\x00"); offset += 4 {
		instruction := binary.BigEndian.Uint32(wrapper[offset : offset+4])
		if instruction>>26 != 18 {
			continue
		}
		displacement := int64(instruction & 0x03fffffc)
		if displacement&0x02000000 != 0 {
			displacement -= 0x04000000
		}
		if instruction&1 == 0 {
			target := int64(wrapperVMA+uint64(offset)) + displacement
			if uint64(target) != clearQoSCalleeVMA && (target < int64(wrapperVMA) || target >= int64(wrapperLimitVMA)) {
				t.Fatalf("relative branch at wrapper+0x%x targets 0x%x outside wrapper", offset, target)
			}
		}
	}
}

func TestBuildWrapperUsesVersionTwoFixedRecords(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{
		{0x3c, 0x00, 0x51, 0x4f, 0x60, 0x00, 0x53, 0x31, 0x90, 0x0c, 0x00, 0x00},
		{0x38, 0x00, 0x00, 0x02, 0xb0, 0x0c, 0x00, 0x04},
		{0x38, 0xa0, 0x00, recordSize},
		{0x38, 0xa0, 0x00, recordSize * 2},
	} {
		if !bytes.Contains(wrapper, field) {
			t.Fatalf("wrapper is missing record field %x", field)
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

func branchOffsetToAny(t *testing.T, code []byte, target uint64) int {
	t.Helper()
	for offset := 0; offset+4 <= len(code); offset += 4 {
		instruction := binary.BigEndian.Uint32(code[offset : offset+4])
		if instruction>>26 != 18 {
			continue
		}
		displacement := int64(instruction & 0x03fffffc)
		if displacement&0x02000000 != 0 {
			displacement -= 0x04000000
		}
		resolved := uint64(int64(wrapperVMA+uint64(offset)) + displacement)
		if resolved == target {
			return offset
		}
	}
	t.Fatalf("branch to 0x%x not found", target)
	return 0
}
