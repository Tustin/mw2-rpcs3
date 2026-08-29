package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildWrapperUsesOpenedFileDescriptorForWriteAndClose(t *testing.T) {
	wrapper, err := buildJoinWrapper()
	if err != nil {
		t.Fatal(err)
	}

	openCallOffset := branchOffsetToFrom(t, wrapper, joinWrapperVMA, cellFsOpenVMA)
	path := []byte("/dev_hdd0/tmp/qos.bin\x00")
	pathAddress := joinWrapperVMA + uint64(bytes.LastIndex(wrapper, path))
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

	writeCallOffset := branchOffsetToFrom(t, wrapper, joinWrapperVMA, cellFsWriteVMA)
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

	closeCallOffset := branchOffsetToFrom(t, wrapper, joinWrapperVMA, cellFsCloseVMA)
	if instruction := binary.BigEndian.Uint32(wrapper[closeCallOffset-4 : closeCallOffset]); instruction != 0x806100f0 {
		t.Fatalf("close descriptor load=%08x want=806100f0", instruction)
	}
}

func TestBuildWrapperRetainsVersionTwoQoSDispatch(t *testing.T) {
	wrapper, err := buildWrapper()
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range [][]byte{
		{0x28, 0x09, 0xa7, 0xbc},
		{0x28, 0x09, 0xa7, 0xa4},
		{0x4b, 0xc1, 0x6c, 0xd0},
		{0x4b, 0x9c, 0x6b, 0x95},
	} {
		if !bytes.Contains(wrapper, field) {
			t.Fatalf("QoS wrapper is missing dispatcher field %x", field)
		}
	}
	for _, joinReturn := range [][]byte{
		{0x28, 0x09, 0xdc, 0x04},
		{0x28, 0x09, 0xdc, 0x34},
		{0x28, 0x09, 0xdc, 0x54},
		{0x28, 0x09, 0xdc, 0x70},
	} {
		if bytes.Contains(wrapper, joinReturn) {
			t.Fatalf("QoS wrapper unexpectedly handles join return %x", joinReturn)
		}
	}
}

func TestBuildWrapperCapturesJoinPipeline(t *testing.T) {
	wrapper, err := buildJoinWrapper()
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafeLoad := range [][]byte{
		{0x88, 0x19, 0x03, 0xd1},
		{0x80, 0x19, 0x03, 0x90},
	} {
		if bytes.Contains(wrapper, unsafeLoad) {
			t.Fatalf("join wrapper retains unsafe controller load %x", unsafeLoad)
		}
	}
	if len(wrapper) > int(wrapperLimitVMA-joinWrapperVMA) {
		t.Fatalf("wrapper size=%d exceeds cave size=%d", len(wrapper), wrapperLimitVMA-joinWrapperVMA)
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
		0x38000000,
		0x980c002b,
		0x900c002c,
		0xfbec0030,
		0xfb6c0038,
		0xfbcc0040,
		0x2c3f0000,
		0x801f0010,
		0xe81f0000,
		0xf80c0058,
		0x801b0010,
		0x801e0010,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
	for _, target := range []uint64{cellFsOpenVMA, cellFsWriteVMA, cellFsCloseVMA} {
		branchOffsetToFrom(t, wrapper, joinWrapperVMA, target)
	}
	for offset, target := range map[int]uint64{
		0x21c: joinTestCalleeVMA,
		0x220: joinHostCalleeVMA,
		0x224: joinStartCalleeVMA,
	} {
		instruction := binary.BigEndian.Uint32(wrapper[offset : offset+4])
		displacement := int64(instruction & 0x03fffffc)
		if displacement&0x02000000 != 0 {
			displacement -= 0x04000000
		}
		resolved := uint64(int64(joinWrapperVMA+uint64(offset)) + displacement)
		if instruction>>26 != 18 || resolved != target || instruction&1 != 0 {
			t.Fatalf("tail branch at 0x%x instruction=%08x target=0x%x", offset, instruction, resolved)
		}
	}
}

func TestBuildWrapperDispatchesJoinStagesByLowReturnAddress(t *testing.T) {
	wrapper, err := buildJoinWrapper()
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
		{
			0x2c, 0x3f, 0x00, 0x00,
			0x41, 0x82, 0x00, 0x14,
			0x80, 0x1f, 0x00, 0x10,
			0x90, 0x0c, 0x00, 0x48,
			0xe8, 0x1f, 0x00, 0x00,
			0xf8, 0x0c, 0x00, 0x58,
		},
	} {
		if !bytes.Contains(wrapper, field) {
			t.Fatalf("wrapper is missing dispatcher field %x", field)
		}
	}
}

func TestBuildWrapperUsesVersionThreeFixedRecords(t *testing.T) {
	wrapper, err := buildJoinWrapper()
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

func TestSecondaryGateContextCentersCallAtVMA(t *testing.T) {
	if got := binary.BigEndian.Uint32(gateSecondaryContext[4:8]); got != 0x4800f3f1 {
		t.Fatalf("secondary gate call=%08x want=4800f3f1", got)
	}
	if got := binary.BigEndian.Uint32(gateSecondaryContext[8:12]); got != 0x60000000 {
		t.Fatalf("secondary gate delay slot=%08x want=60000000", got)
	}
}

func branchOffsetTo(t *testing.T, code []byte, target uint64) int {
	t.Helper()
	return branchOffsetToFrom(t, code, wrapperVMA, target)
}

func branchOffsetToFrom(t *testing.T, code []byte, base, target uint64) int {
	t.Helper()
	for offset := 0; offset+4 <= len(code); offset += 4 {
		instruction := binary.BigEndian.Uint32(code[offset : offset+4])
		address := base + uint64(offset)
		resolved, err := branchTarget(address, instruction)
		if err == nil && resolved == target {
			return offset
		}
	}
	t.Fatalf("branch to 0x%x not found", target)
	return 0
}
