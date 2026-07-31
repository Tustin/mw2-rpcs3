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
	clearQoSCalleeVMA    = uint64(0x320048)
	wrapperVMA           = uint64(0x709280)
	wrapperFileOffset    = uint64(0x6f9280)
	firstLoadFileSize    = uint64(0x6f9280)
	firstLoadVAddr       = uint64(0x10000)
	secondLoadFileOff    = uint64(0x700000)
	cellFsOpenVMA        = uint64(0x526274)
	cellFsWriteVMA       = uint64(0x526334)
	cellFsCloseVMA       = uint64(0x5261f4)
	recordSize           = 52
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
)

type assembler struct {
	base   uint64
	code   []byte
	labels map[string]uint64
	fixups []fixup
}

type fixup struct {
	offset int
	target uint64
	link   bool
	label  string
}

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
	if err := validateCallSite(data, file, abortCallVMA, abortContext); err != nil {
		return fmt.Errorf("abort call: %w", err)
	}
	if err := validateCallSite(data, file, acceptCallVMA, acceptContext); err != nil {
		return fmt.Errorf("accept call: %w", err)
	}

	wrapper, err := buildWrapper()
	if err != nil {
		return fmt.Errorf("build wrapper: %w", err)
	}
	newFirstSize := first.Filesz + uint64(len(wrapper))
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
	for _, callVMA := range []uint64{abortCallVMA, acceptCallVMA} {
		offset, err := vmaToFileOffset(file, callVMA, uint64(len(data)))
		if err != nil {
			return err
		}
		binary.BigEndian.PutUint32(patched[offset:offset+4], encodeBranch(callVMA, wrapperVMA, true))
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
	fmt.Printf("accept call 0x%x -> wrapper, tag 2\n", acceptCallVMA)
	fmt.Printf("record: 52 bytes appended to /dev_hdd0/tmp/mw2_qos.bin\n")
	fmt.Printf("input SHA-256:  %s\n", inputHash)
	fmt.Printf("output SHA-256: %s\n", outputHash)
	fmt.Printf("wrote %s\n", outputPath)
	return nil
}

func validateCallSite(data []byte, file *elf.File, vma uint64, context []byte) error {
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
	if callee != clearQoSCalleeVMA {
		return fmt.Errorf("call at VMA 0x%x resolves to 0x%x, not 0x%x", vma, callee, clearQoSCalleeVMA)
	}
	if binary.BigEndian.Uint32(data[offset+8:offset+12]) != 0x60000000 {
		return fmt.Errorf("instruction after call at VMA 0x%x is not the verified nop", vma)
	}
	return nil
}

func buildWrapper() ([]byte, error) {
	a := &assembler{base: wrapperVMA, labels: map[string]uint64{}}
	a.emit(0xf821ff01)
	a.emit(0x7c0802a6)
	a.emit(0xf8010110)
	a.emit(0xf8410028)
	a.emit(0xf8010048)
	a.emit(0x7c000026)
	a.emit(0xf8010030)
	a.emit(0x7c0102a6)
	a.emit(0xf8010038)
	a.emit(0x7c0902a6)
	a.emit(0xf8010040)
	a.emit(0xf8610050)
	a.emit(0xf8810058)
	a.emit(0xf8a10060)
	a.emit(0xf8c10068)
	a.emit(0xf8e10070)
	a.emit(0xf9010078)
	a.emit(0xf9210080)
	a.emit(0xf9410088)
	a.emit(0xf9610090)
	a.emit(0xf9810098)
	a.emit(0x3d20514f)
	a.emit(0x61295331)
	a.emit(0x912100a0)
	a.emit(0x3d200001)
	a.emit(0x912100a4)
	a.emit(0x39200000)
	a.emit(0xf92100a8)
	a.emit(0x3d200030)
	a.emit(0x3929a394)
	a.emit(0x7c004800)
	a.emit(0x39200002)
	a.branchLabel("copy", false, 0x40820000)
	a.emit(0x39200001)
	a.label("copy")
	a.emit(0x992100a8)
	a.emit(0x81230000)
	a.emit(0x912100b0)
	a.emit(0x81230004)
	a.emit(0x912100b4)
	a.emit(0x81230008)
	a.emit(0x912100b8)
	a.emit(0x8123000c)
	a.emit(0x912100bc)
	a.emit(0x81230010)
	a.emit(0x912100c0)
	a.emit(0x81230014)
	a.emit(0x912100c4)
	a.emit(0x81230018)
	a.emit(0x912100c8)
	a.emit(0x8123001c)
	a.emit(0x912100cc)
	a.emit(0x81230020)
	a.emit(0x912100d0)
	pathHighInstructionOffset := len(a.code)
	a.emit(0x3c600000)
	pathLowInstructionOffset := len(a.code)
	a.emit(0x38630000)
	a.emit(0x38800441)
	a.emit(0x38a100d4)
	a.emit(0x38c001a4)
	a.emit(0x38e00000)
	a.emit(0x39000000)
	a.branchTo(cellFsOpenVMA, true)
	a.emit(0xe8410028)
	a.emit(0x2c030000)
	a.branchLabel("restore", false, 0x40820000)
	a.emit(0x806100a8)
	a.emit(0x388100a0)
	a.emit(0x38a00034)
	a.emit(0x38c100d8)
	a.branchTo(cellFsWriteVMA, true)
	a.emit(0xe8410028)
	a.emit(0x806100a8)
	a.branchTo(cellFsCloseVMA, true)
	a.emit(0xe8410028)
	a.label("restore")
	a.emit(0xe8610050)
	a.emit(0xe8810058)
	a.emit(0xe8a10060)
	a.emit(0xe8c10068)
	a.emit(0xe8e10070)
	a.emit(0xe9010078)
	a.emit(0xe9210080)
	a.emit(0xe9410088)
	a.emit(0xe9610090)
	a.emit(0xe9810098)
	a.emit(0xe8010040)
	a.emit(0x7c0903a6)
	a.emit(0xe8010038)
	a.emit(0x7c0103a6)
	a.emit(0xe8010030)
	a.emit(0x7c0ff120)
	a.emit(0xe8010048)
	a.emit(0xe8410028)
	a.emit(0xe8010110)
	a.emit(0x7c0803a6)
	a.emit(0x38210100)
	a.branchTo(clearQoSCalleeVMA, false)
	for len(a.code)%16 != 0 {
		a.code = append(a.code, 0)
	}
	pathOffset := len(a.code)
	a.code = append(a.code, []byte("/dev_hdd0/tmp/mw2_qos.bin\x00")...)
	for len(a.code)%16 != 0 {
		a.code = append(a.code, 0)
	}
	pathVMA := wrapperVMA + uint64(pathOffset)
	pathHigh := uint32((pathVMA + 0x8000) >> 16)
	pathLow := uint32(pathVMA & 0xffff)
	binary.BigEndian.PutUint32(a.code[pathHighInstructionOffset:pathHighInstructionOffset+4], 0x3c600000|pathHigh)
	binary.BigEndian.PutUint32(a.code[pathLowInstructionOffset:pathLowInstructionOffset+4], 0x38630000|pathLow)
	if err := a.resolve(); err != nil {
		return nil, err
	}
	return a.code, nil
}

func (a *assembler) emit(instruction uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], instruction)
	a.code = append(a.code, encoded[:]...)
}

func (a *assembler) branchTo(target uint64, link bool) {
	a.fixups = append(a.fixups, fixup{offset: len(a.code), target: target, link: link})
	a.emit(0)
}

func (a *assembler) branchLabel(label string, link bool, opcode uint32) {
	a.fixups = append(a.fixups, fixup{offset: len(a.code), link: link, label: label})
	a.emit(opcode)
}

func (a *assembler) label(name string) {
	a.labels[name] = a.base + uint64(len(a.code))
}

func (a *assembler) resolve() error {
	for _, item := range a.fixups {
		target := item.target
		if item.label != "" {
			var ok bool
			target, ok = a.labels[item.label]
			if !ok {
				return fmt.Errorf("unknown label %q", item.label)
			}
		}
		address := a.base + uint64(item.offset)
		current := binary.BigEndian.Uint32(a.code[item.offset : item.offset+4])
		var instruction uint32
		if current&0xfc000000 == 0x40000000 {
			displacement := int64(target) - int64(address)
			if displacement < -0x8000 || displacement > 0x7ffc || displacement%4 != 0 {
				return fmt.Errorf("conditional branch from 0x%x to 0x%x is out of range", address, target)
			}
			instruction = current | uint32(displacement)&0xfffc
		} else {
			instruction = encodeBranch(address, target, item.link)
		}
		binary.BigEndian.PutUint32(a.code[item.offset:item.offset+4], instruction)
	}
	return nil
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
