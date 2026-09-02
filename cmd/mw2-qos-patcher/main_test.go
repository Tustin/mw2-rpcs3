package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildMapCommitWrapperTargetsVerifiedCalleesAndRecord(t *testing.T) {
	wrapper, err := buildMapCommitWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapper) != 0x2d8 {
		t.Fatalf("wrapper size=%#x want=0x2d8", len(wrapper))
	}
	for _, call := range []struct {
		offset int
		target uint64
	}{
		{0x1c, mapCalleeVMA},
		{0xfc, emitWrapperVMA},
		{0x1c8, commitCalleeVMA},
		{0x21c, emitWrapperVMA},
		{0x27c, cellFsOpenVMA},
		{0x29c, cellFsWriteVMA},
		{0x2a4, cellFsCloseVMA},
	} {
		instruction := binary.BigEndian.Uint32(wrapper[call.offset : call.offset+4])
		resolved, err := branchTarget(wrapperVMA+uint64(call.offset), instruction)
		if err != nil || resolved != call.target {
			t.Fatalf("branch at offset %#x resolves to %#x, want %#x: %v", call.offset, resolved, call.target, err)
		}
	}
	path := []byte("/dev_hdd0/tmp/qos-map.bin\x00")
	if !bytes.Contains(wrapper, path) {
		t.Fatalf("wrapper does not contain telemetry path")
	}
	for _, word := range []uint32{0x3d40514f, 0x614a5331, 0x39400006, 0xb14b0004, 0x814b0004, 0x914b0004} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], word)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper missing record instruction %08x", word)
		}
	}
	for _, check := range []struct {
		offset int
		word   uint32
	}{
		{0x160, 0x814b0004},
		{0x22c, 0x914b0004},
	} {
		if got := binary.BigEndian.Uint32(wrapper[check.offset : check.offset+4]); got != check.word {
			t.Fatalf("wrapper word at offset %#x=%08x want=%08x", check.offset, got, check.word)
		}
	}
}

func TestBuildSelectorWrapperCapturesLiveCandidateArray(t *testing.T) {
	wrapper, err := buildSelectorWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapper) > int(selectorWrapperLimit-selectorWrapperVMA) {
		t.Fatalf("wrapper size=%d exceeds cave size=%d", len(wrapper), selectorWrapperLimit-selectorWrapperVMA)
	}
	for _, call := range []struct {
		offset int
		target uint64
	}{
		{28, selectorCalleeVMA},
		{256, cellFsOpenVMA},
		{288, cellFsWriteVMA},
		{300, cellFsCloseVMA},
	} {
		instruction := binary.BigEndian.Uint32(wrapper[call.offset : call.offset+4])
		resolved, err := branchTarget(selectorWrapperVMA+uint64(call.offset), instruction)
		if err != nil || resolved != call.target {
			t.Fatalf("branch at offset %#x resolves to %#x, want %#x: %v", call.offset, resolved, call.target, err)
		}
	}
	if !bytes.HasSuffix(wrapper, []byte("/dev_hdd0/tmp/qos-selector.bin\x00")) {
		t.Fatal("wrapper is missing the selector telemetry path")
	}
	for offset, instruction := range map[int]uint32{
		96:  0x91410044,
		260: 0xe8410028,
		280: 0x80a10044,
		292: 0xe8410028,
		296: 0x80610048,
		304: 0xe8610040,
		308: 0xe8010030,
	} {
		if actual := binary.BigEndian.Uint32(wrapper[offset : offset+4]); actual != instruction {
			t.Fatalf("wrapper instruction at offset %#x=%08x want=%08x", offset, actual, instruction)
		}
	}
	for _, instruction := range []uint32{
		0x81230038, 0x8143003c, 0x1d4a0050, 0x394a0050,
		0x3d605153, 0x616b4531, 0x91610050, 0x90610058,
		0x81630038, 0x9161005c, 0x8163003c, 0x91610060,
		0x1d6b0050, 0x892c0000, 0x99280000, 0x91410044,
		0x80a10044, 0xe8610040, 0x7c0ff120, 0x38210b00, 0x4e800020,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
}

func TestProbeCallsiteMatchesVerifiedSelectorCall(t *testing.T) {
	if probeCallVMA != 0xd5b20 {
		t.Fatalf("probe call VMA=%#x want=0xd5b20", probeCallVMA)
	}
	want := []byte{
		0x39, 0x01, 0x00, 0x70,
		0x4b, 0xff, 0xc9, 0x49,
		0x54, 0x63, 0x06, 0x3e,
		0x2f, 0x83, 0x00, 0x00,
	}
	if !bytes.Equal(probeContext, want) {
		t.Fatalf("probe context=% x want=% x", probeContext, want)
	}
	resolved, err := branchTarget(probeCallVMA, binary.BigEndian.Uint32(probeContext[4:8]))
	if err != nil || resolved != probeCalleeVMA {
		t.Fatalf("probe call resolves to %#x, want %#x: %v", resolved, probeCalleeVMA, err)
	}
}

func TestBuildProbeWrapperCapturesSelectedPartyStateOnce(t *testing.T) {
	wrapper, err := buildProbeWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapper) != 0x1fc {
		t.Fatalf("wrapper size=%#x want=0x1fc", len(wrapper))
	}
	if probeWrapperVMA+uint64(len(wrapper)) > selectorWrapperLimit {
		t.Fatalf("wrapper end=%#x exceeds cave limit=%#x", probeWrapperVMA+uint64(len(wrapper)), selectorWrapperLimit)
	}
	for _, call := range []struct {
		offset int
		target uint64
	}{
		{84, probeCalleeVMA},
		{468, probeCalleeVMA},
		{324, cellFsOpenVMA},
		{356, cellFsWriteVMA},
		{368, cellFsCloseVMA},
	} {
		instruction := binary.BigEndian.Uint32(wrapper[call.offset : call.offset+4])
		resolved, err := branchTarget(probeWrapperVMA+uint64(call.offset), instruction)
		if err != nil || resolved != call.target {
			t.Fatalf("branch at offset %#x resolves to %#x, want %#x: %v", call.offset, resolved, call.target, err)
		}
	}
	path := []byte("/dev_hdd0/tmp/qos-probe.bin\x00")
	if !bytes.HasSuffix(wrapper, path) {
		t.Fatal("wrapper is missing the selected-party telemetry path")
	}
	pathAddress := probeWrapperVMA + uint64(bytes.LastIndex(wrapper, path))
	if actual := binary.BigEndian.Uint32(wrapper[296:300]); actual != 0x3c600000|uint32(pathAddress>>16) {
		t.Fatalf("path lis=%08x want=%08x", actual, 0x3c600000|uint32(pathAddress>>16))
	}
	if actual := binary.BigEndian.Uint32(wrapper[300:304]); actual != 0x60630000|uint32(pathAddress&0xffff) {
		t.Fatalf("path ori=%08x want=%08x", actual, 0x60630000|uint32(pathAddress&0xffff))
	}
	for _, instruction := range []uint32{
		0x3d800075, 0x618ce340, 0x800c0000, 0x2f800000, 0x409e016c,
		0x38000001, 0x900c0000, 0x3d605052, 0x616b4231, 0xb1610088,
		0xb161008a, 0x814b0038, 0x914100b8, 0x814b003c, 0x914100bc,
		0x89490010, 0x994100c0, 0x88e901e0, 0x98ea0000, 0x38a00100,
		0xe8610078, 0x7c0ff120, 0x38210180, 0xe8610038, 0xe9410070,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
}

func TestBuildJoinStateWrapperCapturesBeforeAndAfterJoinStart(t *testing.T) {
	wrapper, err := buildJoinStateWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapper) != 0x17f {
		t.Fatalf("wrapper size=%#x want=0x17f", len(wrapper))
	}
	if joinStateWrapperVMA+uint64(len(wrapper)) > selectorWrapperLimit {
		t.Fatalf("wrapper end=%#x exceeds cave limit=%#x", joinStateWrapperVMA+uint64(len(wrapper)), selectorWrapperLimit)
	}
	for _, call := range []struct {
		offset int
		target uint64
	}{
		{140, joinStartCalleeVMA},
		{280, cellFsOpenVMA},
		{312, cellFsWriteVMA},
		{324, cellFsCloseVMA},
	} {
		instruction := binary.BigEndian.Uint32(wrapper[call.offset : call.offset+4])
		resolved, err := branchTarget(joinStateWrapperVMA+uint64(call.offset), instruction)
		if err != nil || resolved != call.target {
			t.Fatalf("branch at offset %#x resolves to %#x, want %#x: %v", call.offset, resolved, call.target, err)
		}
	}
	path := []byte("/dev_hdd0/tmp/qos-join.bin\x00")
	if !bytes.HasSuffix(wrapper, path) {
		t.Fatal("wrapper is missing the join-state telemetry path")
	}
	pathAddress := joinStateWrapperVMA + uint64(bytes.LastIndex(wrapper, path))
	if actual := binary.BigEndian.Uint32(wrapper[252:256]); actual != 0x3c600000|uint32(pathAddress>>16) {
		t.Fatalf("path lis=%08x want=%08x", actual, 0x3c600000|uint32(pathAddress>>16))
	}
	if actual := binary.BigEndian.Uint32(wrapper[256:260]); actual != 0x60630000|uint32(pathAddress&0xffff) {
		t.Fatalf("path ori=%08x want=%08x", actual, 0x60630000|uint32(pathAddress&0xffff))
	}
	if bytes.Contains(wrapper, wordsToBytes([]uint32{0x3d800075, 0x618ce344})) {
		t.Fatal("join-state wrapper reuses the QoS commit telemetry guard")
	}
	if bytes.Contains(wrapper, wordsToBytes([]uint32{0x3d800075, 0x618ce34c})) {
		t.Fatal("join-state wrapper guard overlaps the QoS map record")
	}
	if actual := binary.BigEndian.Uint32(wrapper[36:40]); actual != 0x60000000 {
		t.Fatalf("join-state capture gate=%08x want unconditional nop", actual)
	}
	if joinStateTelemetryGuardVMA < mapRecordVMA+recordSize {
		t.Fatalf("join guard=%#x overlaps map record ending at %#x", joinStateTelemetryGuardVMA, mapRecordVMA+recordSize)
	}
	for _, instruction := range []uint32{
		0x3d800075, 0x618ce3a8, 0x38000001, 0x900c0000, 0x3d604a53,
		0x616b5431, 0xb1610084, 0xb1610086, 0x93610094, 0x39231600,
		0x393b1600, 0x394101d0, 0x39410300, 0x39410430, 0x39000130,
		0x38000002, 0x900c0000, 0x38a004e0, 0xe8610050, 0x38210580,
		0x4e800020,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
}

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

func TestBuildGateWrapperPreservesHookReturnAndCallee(t *testing.T) {
	wrapper, err := buildGateWrapper()
	if err != nil {
		t.Fatal(err)
	}

	commonOffset := 96
	for index, target := range []uint64{gateJoinCalleeVMA, gateStateCalleeVMA, gatePrimaryCalleeVMA, gateSecondCalleeVMA, gateJoinCalleeVMA, gateJoinCalleeVMA} {
		offset := index * 16
		if instruction := binary.BigEndian.Uint32(wrapper[offset : offset+4]); instruction != 0x38000000|uint32(index+1) {
			t.Fatalf("stage %d load=%08x", index+1, instruction)
		}
		if instruction := binary.BigEndian.Uint32(wrapper[offset+4 : offset+8]); instruction != 0x3d800000|uint32(target>>16) {
			t.Fatalf("stage %d callee high=%08x", index+1, instruction)
		}
		if instruction := binary.BigEndian.Uint32(wrapper[offset+8 : offset+12]); instruction != 0x618c0000|uint32(target&0xffff) {
			t.Fatalf("stage %d callee low=%08x", index+1, instruction)
		}
		instruction := binary.BigEndian.Uint32(wrapper[offset+12 : offset+16])
		displacement := int64(instruction & 0x03fffffc)
		if displacement&0x02000000 != 0 {
			displacement -= 0x04000000
		}
		resolved := uint64(int64(gateWrapperVMA+uint64(offset+12)) + displacement)
		if instruction>>26 != 18 || instruction&1 != 0 || resolved != gateWrapperVMA+uint64(commonOffset) {
			t.Fatalf("stage %d common branch=%08x resolved=0x%x", index+1, instruction, resolved)
		}
	}

	if instruction := binary.BigEndian.Uint32(wrapper[commonOffset+4 : commonOffset+8]); instruction != 0xf8010020 {
		t.Fatalf("stage save=%08x want=f8010020", instruction)
	}
	if instruction := binary.BigEndian.Uint32(wrapper[commonOffset+8 : commonOffset+12]); instruction != 0xf9810028 {
		t.Fatalf("callee save=%08x want=f9810028", instruction)
	}
	for _, target := range []uint64{cellFsOpenVMA, cellFsWriteVMA, cellFsCloseVMA} {
		branchOffsetToFrom(t, wrapper, gateWrapperVMA, target)
	}
	if !bytes.HasSuffix(wrapper, []byte("/dev_hdd0/tmp/qos.bin\x00")) {
		t.Fatal("wrapper is missing the telemetry path")
	}
	for _, instruction := range []uint32{0x38810080, 0x38a00060, 0x80610070, 0xe86100b8, 0xe8010040, 0x7c0ff120, 0xe8010030, 0x7c0803a6, 0x38210180, 0x4e800020} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
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

func TestBuildDecisionWrapperCapturesPromotionStateAndRestoresComparison(t *testing.T) {
	wrapper, err := buildDecisionWrapper()
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapper) > int(wrapperLimitVMA-decisionWrapperVMA) {
		t.Fatalf("wrapper size=%d exceeds cave size=%d", len(wrapper), wrapperLimitVMA-decisionWrapperVMA)
	}
	if bytes.Contains(wrapper, []byte("/dev_hdd0/tmp/qos.bin")) {
		t.Fatal("decision wrapper must not perform filesystem telemetry")
	}
	for _, target := range []uint64{cellFsOpenVMA, cellFsWriteVMA, cellFsCloseVMA} {
		for offset := 0; offset+4 <= len(wrapper); offset += 4 {
			instruction := binary.BigEndian.Uint32(wrapper[offset : offset+4])
			if instruction>>26 != 18 || instruction&1 == 0 {
				continue
			}
			displacement := int64(int32(instruction<<6) >> 6)
			if uint64(int64(decisionWrapperVMA+uint64(offset))+displacement) == target {
				t.Fatalf("decision wrapper calls filesystem import 0x%x", target)
			}
		}
	}
	guardLoad := wordsToBytes([]uint32{0x3d800075, 0x618ce340, 0x800c0000, 0x2f800000})
	guardOffset := bytes.Index(wrapper, guardLoad)
	if guardOffset < 0 || guardOffset+20 > len(wrapper) {
		t.Fatal("wrapper is missing the one-shot telemetry guard")
	}
	guardBranch := binary.BigEndian.Uint32(wrapper[guardOffset+16 : guardOffset+20])
	if guardBranch&0xffff0003 != 0x409e0000 {
		t.Fatalf("one-shot guard branch=%08x want bne", guardBranch)
	}
	guardTarget := guardOffset + 16 + int(int16(guardBranch&0xfffc))
	firstRestore := bytes.Index(wrapper, []byte{0xe8, 0x01, 0x00, 0x30})
	if guardTarget != firstRestore {
		t.Fatalf("one-shot guard target=%d want restore offset=%d", guardTarget, firstRestore)
	}
	if !bytes.Contains(wrapper, wordsToBytes([]uint32{0x38000001, 0x900c0000, 0x398c0008})) {
		t.Fatal("wrapper does not arm the one-shot guard and select the snapshot buffer")
	}
	if bytes.Contains(wrapper, []byte{0x88, 0x00, 0x00, 0x0c}) || bytes.Contains(wrapper, []byte{0x88, 0x09, 0x00, 0x0c}) {
		t.Fatal("decision wrapper repeats the load that already ran before the hook")
	}
	for _, instruction := range []uint32{
		0x3c00514f, 0x60005331, 0x38000005, 0x980c0006, 0x980c0007,
		0x801b05b0, 0x801b0e4c, 0x801b0e50, 0x801b0e1c, 0x801b0e20,
		0x80152100, 0x7c0ff120, 0x38210040, 0x2f800000, 0x4e800020,
	} {
		var encoded [4]byte
		binary.BigEndian.PutUint32(encoded[:], instruction)
		if !bytes.Contains(wrapper, encoded[:]) {
			t.Fatalf("wrapper is missing instruction %08x", instruction)
		}
	}
	comparison := bytes.LastIndex(wrapper, []byte{0x2f, 0x80, 0x00, 0x00})
	if comparison < 0 || comparison+8 > len(wrapper) || binary.BigEndian.Uint32(wrapper[comparison+4:comparison+8]) != 0x4e800020 {
		t.Fatal("overwritten comparison is not immediately followed by blr")
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

func TestPackageSELFVerifiesRoundTripBeforeInstall(t *testing.T) {
	directory := t.TempDir()
	elfPath := filepath.Join(directory, "patched.elf")
	selfPath := filepath.Join(directory, "default_mp.self")
	templatePath := filepath.Join(directory, "template.self")
	scetoolDir := filepath.Join(directory, "self")
	for path, data := range map[string][]byte{
		elfPath:      []byte("patched elf"),
		templatePath: []byte("template"),
		filepath.Join(scetoolDir, "tool", "scetool.exe"): []byte("tool"),
		filepath.Join(scetoolDir, "data", "keys"):        []byte("keys"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	calls := 0
	runner := func(gotDir string, args ...string) ([]byte, error) {
		calls++
		if gotDir != scetoolDir {
			t.Fatalf("scetool directory=%q want=%q", gotDir, scetoolDir)
		}
		switch calls {
		case 1:
			if len(args) != 12 || args[0] != "-v" || args[1] != "-t" || args[2] != templatePath || args[9] != "-e" || args[10] != elfPath || args[11] != selfPath+".tmp" {
				t.Fatalf("package arguments=%q", args)
			}
			return nil, os.WriteFile(args[11], []byte("self"), 0o644)
		case 2:
			if len(args) != 4 || args[0] != "-v" || args[1] != "-d" || args[2] != selfPath+".tmp" || args[3] != selfPath+".roundtrip.tmp" {
				t.Fatalf("decrypt arguments=%q", args)
			}
			data, err := os.ReadFile(elfPath)
			if err != nil {
				return nil, err
			}
			return nil, os.WriteFile(args[3], data, 0o644)
		default:
			t.Fatalf("unexpected scetool call %d", calls)
			return nil, nil
		}
	}

	if err := packageSELF(elfPath, selfPath, scetoolDir, templatePath, runner); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("scetool calls=%d want=2", calls)
	}
	if data, err := os.ReadFile(selfPath); err != nil || string(data) != "self" {
		t.Fatalf("SELF output=%q err=%v", data, err)
	}
	for _, path := range []string{selfPath + ".tmp", selfPath + ".roundtrip.tmp"} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("temporary output remains: %s", path)
		}
	}
}

func TestPackageSELFRejectsRoundTripMismatch(t *testing.T) {
	directory := t.TempDir()
	elfPath := filepath.Join(directory, "patched.elf")
	selfPath := filepath.Join(directory, "default_mp.self")
	templatePath := filepath.Join(directory, "template.self")
	scetoolDir := filepath.Join(directory, "self")
	for path, data := range map[string][]byte{
		elfPath:      []byte("patched elf"),
		templatePath: []byte("template"),
		filepath.Join(scetoolDir, "tool", "scetool.exe"): []byte("tool"),
		filepath.Join(scetoolDir, "data", "keys"):        []byte("keys"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	runner := func(_ string, args ...string) ([]byte, error) {
		if args[0] == "-v" && args[1] == "-t" {
			return nil, os.WriteFile(args[len(args)-1], []byte("self"), 0o644)
		}
		return nil, os.WriteFile(args[len(args)-1], []byte("wrong elf"), 0o644)
	}
	if err := packageSELF(elfPath, selfPath, scetoolDir, templatePath, runner); err == nil || err.Error() != "decrypted SELF does not match the patched ELF" {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(selfPath); !os.IsNotExist(err) {
		t.Fatalf("invalid SELF was installed")
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
