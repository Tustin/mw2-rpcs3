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
	expectedInputSHA256 = "5ecae7aebdffa8b5aa62f087a81f1b9c20f9c4b3dbdc4d41c2c00e65f1072041"
	targetCalleeVMA     = uint64(0x30a838)
	powerPCNOP          = uint32(0x60000000)
)

var callSitePattern = []byte{
	0x7f, 0xe3, 0xfb, 0x78,
	0x4b, 0xff, 0xe5, 0x3d,
	0x7f, 0xe3, 0xfb, 0x78,
	0x4b, 0xf8, 0x92, 0xbd,
	0x60, 0x00, 0x00, 0x00,
	0x7f, 0xe3, 0xfb, 0x78,
	0x48, 0x00, 0xdf, 0x29,
	0x60, 0x00, 0x00, 0x00,
	0x7f, 0xe3, 0xfb, 0x78,
	0x48, 0x00, 0xdc, 0xbd,
	0x60, 0x00, 0x00, 0x00,
	0x7f, 0xe3, 0xfb, 0x78,
	0x48, 0x1e, 0x01, 0x99,
	0xe8, 0x41, 0x00, 0x28,
}

func main() {
	input := flag.String("input", "captures/default_mp.elf", "decrypted MW2 multiplayer ELF")
	output := flag.String("output", "default_mp.no-playercard.elf", "patched ELF output")
	force := flag.Bool("force", false, "accept a non-reference input SHA-256 if all byte checks pass")
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
		return fmt.Errorf("unexpected input SHA-256 %s; expected %s (use -force only for a verified equivalent build)", inputHash, expectedInputSHA256)
	}

	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parse ELF: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2MSB || file.Machine != elf.EM_PPC64 {
		return fmt.Errorf("unsupported ELF format: class=%s data=%s machine=%s", file.Class, file.Data, file.Machine)
	}

	matches := findAll(data, callSitePattern)
	if len(matches) != 1 {
		return fmt.Errorf("expected one validated caller pattern, found %d", len(matches))
	}

	callFileOffset := uint64(matches[0] + 24)
	callVMA, err := fileOffsetToVMA(file, callFileOffset)
	if err != nil {
		return err
	}
	instruction := binary.BigEndian.Uint32(data[callFileOffset : callFileOffset+4])
	callee, err := branchTarget(callVMA, instruction)
	if err != nil {
		return err
	}
	if callee != targetCalleeVMA {
		return fmt.Errorf("candidate call at VMA 0x%x resolves to 0x%x, not 0x%x", callVMA, callee, targetCalleeVMA)
	}

	calleeOffset, err := vmaToFileOffset(file, targetCalleeVMA, uint64(len(data)))
	if err != nil {
		return err
	}
	calleePrefix := []byte{
		0x81, 0x22, 0x6d, 0x04,
		0x7c, 0x08, 0x02, 0xa6,
		0xf8, 0x21, 0xff, 0x71,
		0xfb, 0xa1, 0x00, 0x78,
		0x3f, 0xa9, 0x00, 0x04,
		0xfb, 0x81, 0x00, 0x70,
		0x3f, 0x89, 0x00, 0x02,
		0xf8, 0x01, 0x00, 0xa0,
	}
	if calleeOffset+uint64(len(calleePrefix)) > uint64(len(data)) || !bytes.Equal(data[calleeOffset:calleeOffset+uint64(len(calleePrefix))], calleePrefix) {
		return fmt.Errorf("callee prefix at VMA 0x%x does not match the verified build", targetCalleeVMA)
	}

	patched := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(patched[callFileOffset:callFileOffset+4], powerPCNOP)

	mode := os.FileMode(0o644)
	if info, statErr := os.Stat(inputPath); statErr == nil {
		mode = info.Mode().Perm()
	}
	if err := writeAtomic(outputPath, patched, mode); err != nil {
		return err
	}

	outputHash := fmt.Sprintf("%x", sha256.Sum256(patched))
	fmt.Printf("patched player-card call: VMA 0x%x, file offset 0x%x\n", callVMA, callFileOffset)
	fmt.Printf("original instruction: %08x; replacement: %08x\n", instruction, powerPCNOP)
	fmt.Printf("input SHA-256:  %s\n", inputHash)
	fmt.Printf("output SHA-256: %s\n", outputHash)
	fmt.Printf("wrote %s\n", outputPath)
	return nil
}

func findAll(data, pattern []byte) []int {
	var matches []int
	for start := 0; start <= len(data)-len(pattern); {
		index := bytes.Index(data[start:], pattern)
		if index < 0 {
			break
		}
		matches = append(matches, start+index)
		start += index + 1
	}
	return matches
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

func fileOffsetToVMA(file *elf.File, offset uint64) (uint64, error) {
	for _, program := range file.Progs {
		if program.Type == elf.PT_LOAD && offset >= program.Off && offset < program.Off+program.Filesz {
			return program.Vaddr + offset - program.Off, nil
		}
	}
	return 0, fmt.Errorf("file offset 0x%x is not in a loadable segment", offset)
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
