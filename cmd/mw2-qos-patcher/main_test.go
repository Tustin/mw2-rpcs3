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

	openCallOffset := branchOffsetTo(t, wrapper, cellFsOpenVMA)
	path := []byte("/dev_hdd0/tmp/qos.bin\x00")
	pathAddress := wrapperVMA + uint64(bytes.LastIndex(wrapper, path))
	for offset, want := range map[int]uint32{
		-28: 0x3c600000 | uint32(pathAddress>>16),
		-24: 0x60630000 | uint32(pathAddress&0xffff),
		-20: 0x38800441,
		-16: 0x38a100f0,
		-12: 0x38c00000,
		-8:  0x38e00000,
		-4:  0x39000000,
	} {
		if instruction := binary.BigEndian.Uint32(wrapper[openCallOffset+offset : openCallOffset+offset+4]); instruction != want {
			t.Fatalf("open argument instruction at %+d=%08x want=%08x", offset, instruction, want)
		}
	}

	writeCallOffset := branchOffsetTo(t, wrapper, cellFsWriteVMA)
	for offset, want := range map[int]uint32{
		-16: 0x806100f0,
		-12: 0x38810100,
		-8:  0x38a00060,
		-4:  0x38c100e0,
	} {
		if instruction := binary.BigEndian.Uint32(wrapper[writeCallOffset+offset : writeCallOffset+offset+4]); instruction != want {
			t.Fatalf("write argument instruction at %+d=%08x want=%08x", offset, instruction, want)
		}
	}

	closeCallOffset := branchOffsetTo(t, wrapper, cellFsCloseVMA)
	if instruction := binary.BigEndian.Uint32(wrapper[closeCallOffset-4 : closeCallOffset]); instruction != 0x806100f0 {
		t.Fatalf("close descriptor load=%08x want=806100f0", instruction)
	}
}

func TestBuildWrapperCapturesJoinPipeline(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapper) > int(wrapperLimitVMA-wrapperVMA) {
		t.Fatalf("wrapper size=%d exceeds cave size=%d", len(wrapper), wrapperLimitVMA-wrapperVMA)
	}
	if !bytes.HasSuffix(wrapper, []byte("/dev_hdd0/tmp/qos.bin\x00")) {
		t.Fatal("wrapper is missing the telemetry path")
	}
	for _, instruction := range []uint32{
		0x38000003,
		0xb00c0004,
		0xb10c0008,
		0x80010538,
		0x900c0020,
		0x80010534,
		0x900c0024,
		0xa0010530,
		0xb00c0028,
		0x881c014e,
		0x980c002a,
		0x881903d1,
		0x980c002b,
		0x80190390,
		0x900c002c,
		0xfbec0030,
		0xfb6c0038,
		0xfbcc0040,
		0x801f0010,
		0x801b0010,
		0x801e0010,
		0xe81f0000,
		0xf80c0058,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
	for _, target := range []uint64{cellFsOpenVMA, cellFsWriteVMA, cellFsCloseVMA} {
		branchOffsetTo(t, wrapper, target)
	}
	for offset, target := range map[int]uint64{
		0x214: joinTestCalleeVMA,
		0x218: joinHostCalleeVMA,
		0x21c: joinStartCalleeVMA,
	} {
		instruction := binary.BigEndian.Uint32(wrapper[offset : offset+4])
		displacement := int64(instruction & 0x03fffffc)
		if displacement&0x02000000 != 0 {
			displacement -= 0x04000000
		}
		resolved := uint64(int64(wrapperVMA+uint64(offset)) + displacement)
		if instruction>>26 != 18 || resolved != target || instruction&1 != 0 {
			t.Fatalf("tail branch at 0x%x instruction=%08x target=0x%x", offset, instruction, resolved)
		}
	}
}

func TestBuildWrapperDispatchesJoinStagesByLowReturnAddress(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{
		{0x28, 0x09, 0xdc, 0x04},
		{0x28, 0x09, 0xdc, 0x34},
		{0x28, 0x09, 0xdc, 0x54},
		{0x28, 0x09, 0xdc, 0x70},
		{0x39, 0x00, 0x00, 0x01},
		{0x39, 0x00, 0x00, 0x02},
		{0x39, 0x00, 0x00, 0x03},
		{0x39, 0x00, 0x00, 0x04},
		{0x39, 0x00, 0x00, 0x05},
	} {
		if !bytes.Contains(wrapper, field) {
			t.Fatalf("wrapper is missing dispatcher field %x", field)
		}
	}
}

func TestBuildWrapperUsesVersionThreeFixedRecords(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{
		{0x3c, 0x00, 0x51, 0x4f, 0x60, 0x00, 0x53, 0x31, 0x90, 0x0c, 0x00, 0x00},
		{0x38, 0x00, 0x00, 0x03, 0xb0, 0x0c, 0x00, 0x04},
		{0x38, 0xa0, 0x00, recordSize},
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
