package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
)

const (
	expectedInputSHA256  = "16523486aa1c148eb7e19c40ae98763ec2c85b660dabd46131adb34f815495fb"
	abortCallVMA         = uint64(0x2fa390)
	acceptCallVMA        = uint64(0x2fa7a0)
	cffCallVMA           = uint64(0x2fa7b8)
	joinTestCallVMA      = uint64(0x2fdc00)
	joinHostOneCallVMA   = uint64(0x2fdc30)
	joinHostTwoCallVMA   = uint64(0x2fdc50)
	joinStartCallVMA     = uint64(0x2fdc6c)
	joinRejectCallVMA    = uint64(0x2fdc90)
	clearQoSCalleeVMA    = uint64(0x320048)
	cffCalleeVMA         = uint64(0xcff28)
	joinTestCalleeVMA    = uint64(0xd2468)
	joinHostCalleeVMA    = uint64(0xd26e0)
	joinStartCalleeVMA   = uint64(0xced10)
	wrapperVMA           = uint64(0x709280)
	wrapperLimitVMA      = uint64(0x709660)
	wrapperFileOffset    = uint64(0x6f9280)
	firstLoadFileSize    = uint64(0x6f9280)
	firstLoadVAddr       = uint64(0x10000)
	secondLoadFileOff    = uint64(0x700000)
	cellFsOpenVMA        = uint64(0x526274)
	cellFsWriteVMA       = uint64(0x526334)
	cellFsCloseVMA       = uint64(0x5261f4)
	recordSize           = 96
	firstProgramHeader   = 64
	programFileSizeOff   = firstProgramHeader + 32
	programMemorySizeOff = firstProgramHeader + 40
)

var (
	abortContext = []byte{
		0x7e, 0x83, 0xa3, 0x78,
		0x48, 0x02, 0x5c, 0xb9,
		0x60, 0x00, 0x00, 0x00,
		0x7e, 0x63, 0x9b, 0x78,
		0x4b, 0xee, 0xb2, 0x25,
	}
	acceptContext = []byte{
		0x7e, 0x83, 0xa3, 0x78,
		0x48, 0x02, 0x58, 0xa9,
		0x60, 0x00, 0x00, 0x00,
		0x7e, 0x63, 0x9b, 0x78,
		0x4b, 0xee, 0xae, 0x15,
	}
	cffContext = []byte{
		0x7a, 0x43, 0x00, 0x20,
		0x4b, 0xdd, 0x57, 0x71,
		0x60, 0x00, 0x00, 0x00,
		0x83, 0x9b, 0x05, 0xb0,
		0x83, 0xbb, 0x0e, 0x4c,
	}
	joinTestContext = []byte{
		0x39, 0x01, 0x00, 0x70,
		0x4b, 0xdd, 0x48, 0x69,
		0x60, 0x00, 0x00, 0x00,
		0x54, 0x7d, 0x06, 0x3e,
		0x2f, 0x9d, 0x00, 0x00,
	}
	joinHostOneContext = []byte{
		0x9a, 0xdc, 0x01, 0x4e,
		0x4b, 0xdd, 0x4a, 0xb1,
		0x60, 0x00, 0x00, 0x00,
		0x80, 0xa1, 0x00, 0x78,
		0x80, 0xc1, 0x00, 0x74,
	}
	joinHostTwoContext = []byte{
		0x39, 0x00, 0x00, 0x00,
		0x4b, 0xdd, 0x4a, 0x91,
		0x60, 0x00, 0x00, 0x00,
		0x7f, 0xe3, 0xfb, 0x78,
		0x7f, 0xc5, 0xf3, 0x78,
	}
	joinStartContext = []byte{
		0x92, 0xf9, 0x03, 0x90,
		0x4b, 0xdd, 0x10, 0xa5,
		0x60, 0x00, 0x00, 0x00,
		0x80, 0x82, 0x68, 0x9c,
		0x7f, 0x03, 0xc3, 0x78,
	}
	joinRejectContext = []byte{
		0x60, 0x00, 0x00, 0x00,
		0x4b, 0xff, 0xfd, 0x84,
		0x80, 0x82, 0x68, 0xa0,
		0x38, 0x60, 0x00, 0x0e,
		0x4b, 0xee, 0xa6, 0x65,
	}
)

func main() {
	input := flag.String("input", "/mnt/d/Reversing/PS3/self resigner/self/default_mp.elf", "playlist-patched MW2 multiplayer ELF")
	output := flag.String("output", "/mnt/d/Reversing/PS3/self resigner/self/default_mp.qos-telemetry.elf", "QoS telemetry ELF output")
	force := flag.Bool("force", false, "accept a non-reference input SHA-256 if all byte and ELF checks pass")
	flag.Parse()

	if err := run(*input, *output, *force); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(inputPath, outputPath string, force bool) error {
	if inputPath == outputPath {
		return errors.New("input and output paths must differ")
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	inputHash := fmt.Sprintf("%x", sha256.Sum256(data))
	if inputHash != expectedInputSHA256 && !force {
		return fmt.Errorf("unexpected input SHA-256 %s; expected %s", inputHash, expectedInputSHA256)
	}
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parse ELF: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2MSB || file.Machine != elf.EM_PPC64 {
		return fmt.Errorf("unsupported ELF format: class=%s data=%s machine=%s", file.Class, file.Data, file.Machine)
	}
	if len(file.Progs) < 2 {
		return errors.New("ELF has fewer than two program headers")
	}
	first := file.Progs[0]
	second := file.Progs[1]
	if first.Type != elf.PT_LOAD || first.Off != 0 || first.Vaddr != firstLoadVAddr || first.Filesz != firstLoadFileSize || first.Memsz != firstLoadFileSize || first.Flags&elf.PF_X == 0 {
		return fmt.Errorf("unexpected executable LOAD: off=0x%x vaddr=0x%x filesz=0x%x memsz=0x%x flags=%s", first.Off, first.Vaddr, first.Filesz, first.Memsz, first.Flags)
	}
	if second.Type != elf.PT_LOAD || second.Off != secondLoadFileOff || second.Vaddr != 0x710000 {
		return fmt.Errorf("unexpected writable LOAD boundary: off=0x%x vaddr=0x%x", second.Off, second.Vaddr)
	}
	if uint64(len(data)) < secondLoadFileOff {
		return fmt.Errorf("input is shorter than writable LOAD offset 0x%x", secondLoadFileOff)
	}
	if wrapperFileOffset != first.Off+first.Filesz || wrapperVMA != first.Vaddr+first.Filesz {
		return errors.New("wrapper constants do not match the executable LOAD tail")
	}
	if err := validateCallSite(data, file, abortCallVMA, abortContext, clearQoSCalleeVMA); err != nil {
		return fmt.Errorf("abort call: %w", err)
	}
	if err := validateCallSite(data, file, acceptCallVMA, acceptContext, clearQoSCalleeVMA); err != nil {
		return fmt.Errorf("accept call: %w", err)
	}
	if err := validateCallSite(data, file, cffCallVMA, cffContext, cffCalleeVMA); err != nil {
		return fmt.Errorf("CFF call: %w", err)
	}
	for _, site := range []struct {
		name     string
		vma      uint64
		context  []byte
		callee   uint64
		hasDelay bool
	}{
		{"join test", joinTestCallVMA, joinTestContext, joinTestCalleeVMA, true},
		{"join host one", joinHostOneCallVMA, joinHostOneContext, joinHostCalleeVMA, true},
		{"join host two", joinHostTwoCallVMA, joinHostTwoContext, joinHostCalleeVMA, true},
		{"join start", joinStartCallVMA, joinStartContext, joinStartCalleeVMA, true},
		{"join reject", joinRejectCallVMA, joinRejectContext, 0x2fda14, false},
	} {
		if err := validateBranchSite(data, file, site.vma, site.context, site.callee, site.hasDelay); err != nil {
			return fmt.Errorf("%s: %w", site.name, err)
		}
	}

	wrapper, err := buildWrapper()
	if err != nil {
		return fmt.Errorf("build wrapper: %w", err)
	}
	newFirstSize := first.Filesz + uint64(len(wrapper))
	if wrapperVMA+uint64(len(wrapper)) > wrapperLimitVMA {
		return fmt.Errorf("wrapper exceeds verified cave: end 0x%x, limit 0x%x", wrapperVMA+uint64(len(wrapper)), wrapperLimitVMA)
	}
	if newFirstSize > secondLoadFileOff {
		return fmt.Errorf("wrapper overlaps the writable LOAD: executable end 0x%x, writable offset 0x%x", newFirstSize, secondLoadFileOff)
	}
	if secondLoadFileOff-wrapperFileOffset < uint64(len(wrapper)) {
		return errors.New("insufficient file padding for wrapper")
	}
	if !allZero(data[wrapperFileOffset : wrapperFileOffset+uint64(len(wrapper))]) {
		return fmt.Errorf("wrapper target file range 0x%x..0x%x is not zero padding", wrapperFileOffset, wrapperFileOffset+uint64(len(wrapper)))
	}

	patched := append([]byte(nil), data...)
	copy(patched[wrapperFileOffset:], wrapper)
	binary.BigEndian.PutUint64(patched[programFileSizeOff:programFileSizeOff+8], newFirstSize)
	binary.BigEndian.PutUint64(patched[programMemorySizeOff:programMemorySizeOff+8], newFirstSize)
	for _, site := range []struct {
		vma  uint64
		link bool
	}{
		{abortCallVMA, true},
		{acceptCallVMA, true},
		{cffCallVMA, true},
		{joinTestCallVMA, true},
		{joinHostOneCallVMA, true},
		{joinHostTwoCallVMA, true},
		{joinStartCallVMA, true},
		{joinRejectCallVMA, false},
	} {
		offset, err := vmaToFileOffset(file, site.vma, uint64(len(data)))
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint32(patched[offset:offset+4], encodeBranch(site.vma, wrapperVMA, site.link))
	}

	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(inputPath); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := writeAtomic(outputPath, patched, mode); err != nil {
		return err
	}
	outputHash := fmt.Sprintf("%x", sha256.Sum256(patched))
	fmt.Printf("wrapper: VMA 0x%x, file offset 0x%x, size 0x%x\n", wrapperVMA, wrapperFileOffset, len(wrapper))
	fmt.Printf("abort call 0x%x -> wrapper, tag 1\n", abortCallVMA)
	fmt.Printf("accept call 0x%x -> wrapper, tag 2 phase 0\n", acceptCallVMA)
	fmt.Printf("CFF call 0x%x -> wrapper, tag 2 phases 1 and 2\n", cffCallVMA)
	fmt.Printf("join pipeline 0x%x..0x%x -> wrapper, tag 3 stages 1..5\n", joinTestCallVMA, joinRejectCallVMA)
	fmt.Printf("record: %d-byte version-3 records appended to /dev_hdd0/tmp/qos.bin\n", recordSize)
	fmt.Printf("input SHA-256:  %s\n", inputHash)
	fmt.Printf("output SHA-256: %s\n", outputHash)
	fmt.Printf("wrote %s\n", outputPath)
	return nil
}

func validateCallSite(data []byte, file *elf.File, vma uint64, context []byte, expectedCallee uint64) error {
	offset, err := vmaToFileOffset(file, vma-4, uint64(len(data)))
	if err != nil {
		return err
	}
	if offset+uint64(len(context)) > uint64(len(data)) || !bytes.Equal(data[offset:offset+uint64(len(context))], context) {
		return fmt.Errorf("context at VMA 0x%x does not match the verified build", vma-4)
	}
	instruction := binary.BigEndian.Uint32(data[offset+4 : offset+8])
	callee, err := branchTarget(vma, instruction)
	if err != nil {
		return err
	}
	if callee != expectedCallee {
		return fmt.Errorf("call at VMA 0x%x resolves to 0x%x, not 0x%x", vma, callee, expectedCallee)
	}
	if binary.BigEndian.Uint32(data[offset+8:offset+12]) != 0x60000000 {
		return fmt.Errorf("instruction after call at VMA 0x%x is not the verified nop", vma)
	}
	return nil
}

func validateBranchSite(data []byte, file *elf.File, vma uint64, context []byte, expectedCallee uint64, hasDelaySlot bool) error {
	offset, err := vmaToFileOffset(file, vma-4, uint64(len(data)))
	if err != nil {
		return err
	}
	if offset+uint64(len(context)) > uint64(len(data)) || !bytes.Equal(data[offset:offset+uint64(len(context))], context) {
		return fmt.Errorf("context at VMA 0x%x does not match the verified build", vma-4)
	}
	instruction := binary.BigEndian.Uint32(data[offset+4 : offset+8])
	if instruction>>26 != 18 {
		return fmt.Errorf("instruction %08x at VMA 0x%x is not a branch", instruction, vma)
	}
	displacement := int64(instruction & 0x03fffffc)
	if displacement&0x02000000 != 0 {
		displacement -= 0x04000000
	}
	callee := uint64(int64(vma) + displacement)
	if callee != expectedCallee {
		return fmt.Errorf("branch at VMA 0x%x resolves to 0x%x, not 0x%x", vma, callee, expectedCallee)
	}
	if hasDelaySlot && binary.BigEndian.Uint32(data[offset+8:offset+12]) != 0x60000000 {
		return fmt.Errorf("instruction after branch at VMA 0x%x is not the verified nop", vma)
	}
	return nil
}

func buildWrapper() ([]byte, error) {
	wrapper := []byte{
		0xf8, 0x21, 0xfc, 0x01, 0x7c, 0x08, 0x02, 0xa6, 0xf8, 0x01, 0x04, 0x10, 0xf8, 0x41, 0x00, 0x28,
		0x7c, 0x00, 0x00, 0x26, 0xf8, 0x01, 0x00, 0x30, 0x7c, 0x09, 0x02, 0xa6, 0xf8, 0x01, 0x00, 0x38,
		0x7c, 0x01, 0x02, 0xa6, 0xf8, 0x01, 0x00, 0x40, 0xf8, 0x61, 0x00, 0x48, 0xf8, 0x81, 0x00, 0x50,
		0xf8, 0xa1, 0x00, 0x58, 0xf8, 0xc1, 0x00, 0x60, 0xf8, 0xe1, 0x00, 0x68, 0xf9, 0x01, 0x00, 0x70,
		0xf9, 0x21, 0x00, 0x78, 0xf9, 0x41, 0x00, 0x80, 0xf9, 0x61, 0x00, 0x88, 0xf9, 0x81, 0x00, 0x90,
		0x7d, 0x28, 0x02, 0xa6, 0x79, 0x29, 0x04, 0x20, 0x28, 0x09, 0xdc, 0x04, 0x41, 0x82, 0x00, 0x24,
		0x28, 0x09, 0xdc, 0x34, 0x41, 0x82, 0x00, 0x24, 0x28, 0x09, 0xdc, 0x54, 0x41, 0x82, 0x00, 0x24,
		0x28, 0x09, 0xdc, 0x70, 0x41, 0x82, 0x00, 0x24, 0x39, 0x00, 0x00, 0x05, 0x48, 0x00, 0x00, 0x20,
		0x39, 0x00, 0x00, 0x01, 0x48, 0x00, 0x00, 0x18, 0x39, 0x00, 0x00, 0x02, 0x48, 0x00, 0x00, 0x10,
		0x39, 0x00, 0x00, 0x03, 0x48, 0x00, 0x00, 0x08, 0x39, 0x00, 0x00, 0x04, 0x39, 0x81, 0x01, 0x00,
		0x38, 0x00, 0x00, 0x00, 0x39, 0x60, 0x00, 0x0c, 0xf8, 0x0c, 0x00, 0x00, 0x39, 0x8c, 0x00, 0x08,
		0x35, 0x6b, 0xff, 0xff, 0x40, 0x82, 0xff, 0xf4, 0x39, 0x81, 0x01, 0x00, 0x3c, 0x00, 0x51, 0x4f,
		0x60, 0x00, 0x53, 0x31, 0x90, 0x0c, 0x00, 0x00, 0x38, 0x00, 0x00, 0x03, 0xb0, 0x0c, 0x00, 0x04,
		0x38, 0x00, 0x00, 0x03, 0xb0, 0x0c, 0x00, 0x06, 0xb1, 0x0c, 0x00, 0x08, 0xe8, 0x01, 0x00, 0x48,
		0xf8, 0x0c, 0x00, 0x10, 0xe8, 0x01, 0x00, 0x50, 0xf8, 0x0c, 0x00, 0x18, 0x80, 0x01, 0x05, 0x38,
		0x90, 0x0c, 0x00, 0x20, 0x80, 0x01, 0x05, 0x34, 0x90, 0x0c, 0x00, 0x24, 0xa0, 0x01, 0x05, 0x30,
		0xb0, 0x0c, 0x00, 0x28, 0x88, 0x1c, 0x01, 0x4e, 0x98, 0x0c, 0x00, 0x2a, 0x88, 0x19, 0x03, 0xd1,
		0x98, 0x0c, 0x00, 0x2b, 0x80, 0x19, 0x03, 0x90, 0x90, 0x0c, 0x00, 0x2c, 0xfb, 0xec, 0x00, 0x30,
		0xfb, 0x6c, 0x00, 0x38, 0xfb, 0xcc, 0x00, 0x40, 0x80, 0x1f, 0x00, 0x10, 0x90, 0x0c, 0x00, 0x48,
		0x80, 0x1b, 0x00, 0x10, 0x90, 0x0c, 0x00, 0x4c, 0x80, 0x1e, 0x00, 0x10, 0x90, 0x0c, 0x00, 0x50,
		0xe8, 0x1f, 0x00, 0x00, 0xf8, 0x0c, 0x00, 0x58, 0x3c, 0x60, 0x00, 0x70, 0x60, 0x63, 0x94, 0xa0,
		0x38, 0x80, 0x04, 0x41, 0x38, 0xa1, 0x00, 0xf0, 0x38, 0xc0, 0x00, 0x00, 0x38, 0xe0, 0x00, 0x00,
		0x39, 0x00, 0x00, 0x00, 0x4b, 0xe1, 0xce, 0x91, 0xe8, 0x41, 0x00, 0x28, 0x2c, 0x03, 0x00, 0x00,
		0x40, 0x82, 0x00, 0x24, 0x80, 0x61, 0x00, 0xf0, 0x38, 0x81, 0x01, 0x00, 0x38, 0xa0, 0x00, 0x60,
		0x38, 0xc1, 0x00, 0xe0, 0x4b, 0xe1, 0xcf, 0x31, 0xe8, 0x41, 0x00, 0x28, 0x80, 0x61, 0x00, 0xf0,
		0x4b, 0xe1, 0xcd, 0xe5, 0xe8, 0x61, 0x00, 0x48, 0xe8, 0x81, 0x00, 0x50, 0xe8, 0xa1, 0x00, 0x58,
		0xe8, 0xc1, 0x00, 0x60, 0xe8, 0xe1, 0x00, 0x68, 0xe9, 0x01, 0x00, 0x70, 0xe9, 0x21, 0x00, 0x78,
		0xe9, 0x41, 0x00, 0x80, 0xe9, 0x61, 0x00, 0x88, 0xe9, 0x81, 0x00, 0x90, 0xe8, 0x01, 0x00, 0x40,
		0x7c, 0x01, 0x03, 0xa6, 0xe8, 0x01, 0x00, 0x38, 0x7c, 0x09, 0x03, 0xa6, 0xe8, 0x01, 0x00, 0x30,
		0x7c, 0x0f, 0xf1, 0x20, 0xe8, 0x41, 0x00, 0x28, 0xe8, 0x01, 0x04, 0x10, 0x38, 0x21, 0x04, 0x00,
		0x7c, 0x08, 0x03, 0xa6, 0x7d, 0x28, 0x02, 0xa6, 0x79, 0x29, 0x04, 0x20, 0x28, 0x09, 0xdc, 0x04,
		0x41, 0x82, 0x00, 0x24, 0x28, 0x09, 0xdc, 0x34, 0x41, 0x82, 0x00, 0x20, 0x28, 0x09, 0xdc, 0x54,
		0x41, 0x82, 0x00, 0x18, 0x28, 0x09, 0xdc, 0x70, 0x41, 0x82, 0x00, 0x14, 0x80, 0x82, 0x68, 0xa0,
		0x4e, 0x80, 0x00, 0x20, 0x4b, 0x9c, 0x8f, 0xd4, 0x4b, 0x9c, 0x92, 0x48, 0x4b, 0x9c, 0x58, 0x74,
		0x2f, 0x64, 0x65, 0x76, 0x5f, 0x68, 0x64, 0x64, 0x30, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x71, 0x6f,
		0x73, 0x2e, 0x62, 0x69, 0x6e, 0x00,
	}
	return wrapper, nil
}

func encodeBranch(address, target uint64, link bool) uint32 {
	displacement := int64(target) - int64(address)
	instruction := uint32(0x48000000) | uint32(displacement)&0x03fffffc
	if link {
		instruction |= 1
	}
	return instruction
}

func branchTarget(address uint64, instruction uint32) (uint64, error) {
	if instruction>>26 != 18 || instruction&1 == 0 {
		return 0, fmt.Errorf("instruction %08x at VMA 0x%x is not a branch-and-link", instruction, address)
	}
	displacement := int64(instruction & 0x03fffffc)
	if displacement&0x02000000 != 0 {
		displacement -= 0x04000000
	}
	if instruction&2 != 0 {
		return uint64(displacement), nil
	}
	return uint64(int64(address) + displacement), nil
}

func vmaToFileOffset(file *elf.File, address, fileSize uint64) (uint64, error) {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || address < program.Vaddr || address >= program.Vaddr+program.Filesz {
			continue
		}
		offset := program.Off + address - program.Vaddr
		if offset >= fileSize {
			return 0, fmt.Errorf("VMA 0x%x maps outside the input file", address)
		}
		return offset, nil
	}
	return 0, fmt.Errorf("VMA 0x%x is not file-backed", address)
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporary := file.Name()
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(temporary)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temporary output: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("output already exists: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output path: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("install output: %w", err)
	}
	ok = true
	return nil
}
