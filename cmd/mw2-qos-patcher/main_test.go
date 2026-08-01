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
		-16: 0x38a103f0,
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
		-16: 0x806103f0,
		-12: 0x38810128,
		-8:  0x7f65db78,
		-4:  0x38c103e0,
	} {
		if instruction := binary.BigEndian.Uint32(wrapper[writeCallOffset+offset : writeCallOffset+offset+4]); instruction != want {
			t.Fatalf("write argument instruction at %+d=%08x want=%08x", offset, instruction, want)
		}
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
	if !bytes.HasSuffix(wrapper, []byte("/dev_hdd0/tmp/qos.bin\x00")) {
		t.Fatal("wrapper is missing the telemetry path")
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
		0x3b600060,
		0x3b6000c0,
		0x7f65db78,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
	clearOffset := branchOffsetToAny(t, wrapper, clearQoSCalleeVMA)
	if instruction := binary.BigEndian.Uint32(wrapper[clearOffset : clearOffset+4]); instruction&1 != 0 {
		t.Fatalf("clear-QoS branch=%08x has link bit set", instruction)
	}
	for _, target := range []uint64{cffCalleeVMA, cellFsOpenVMA, cellFsWriteVMA, cellFsCloseVMA} {
		branchOffsetTo(t, wrapper, target)
	}
	for offset := 0; offset+4 <= len(wrapper)-len("/dev_hdd0/tmp/qos.bin\x00"); offset += 4 {
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

func TestBuildWrapperDispatchesByLowReturnAddress(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	for offset, want := range map[int]uint32{
		0x60: 0x7d2802a6,
		0x64: 0x79290420,
		0x68: 0x2809a7bc,
		0x6c: 0x41820090,
		0x70: 0x39000001,
		0x74: 0x2809a7a4,
		0x78: 0x40820008,
		0x7c: 0x39000002,
		0x80: 0x39200000,
		0x84: 0x7c6a1b78,
	} {
		if instruction := binary.BigEndian.Uint32(wrapper[offset : offset+4]); instruction != want {
			t.Fatalf("dispatcher instruction at wrapper+0x%x=%08x want=%08x", offset, instruction, want)
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
		{0x3b, 0x60, 0x00, recordSize},
		{0x3b, 0x60, 0x00, recordSize * 2},
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
