package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/josh/mw2-rpcs3/internal/capture"
	"github.com/josh/mw2-rpcs3/internal/protocol"
)

func main() {
	max := flag.Uint("max-frame", 1<<20, "maximum payload bytes")
	jsonl := flag.Bool("jsonl", false, "read capture JSONL instead of raw frames")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: mw2-inspect [-jsonl] FILE")
		os.Exit(2)
	}
	file, err := os.Open(flag.Arg(0))
	if err != nil {
		fatal(err)
	}
	defer file.Close()
	if *jsonl {
		inspectJSONL(file, uint32(*max))
		return
	}
	inspectFrames(file, uint32(*max))
}

func inspectFrames(r io.Reader, max uint32) {
	for index := 0; ; index++ {
		frame, err := protocol.ReadFrame(r, max)
		if err == io.EOF {
			return
		}
		if err != nil {
			fatal(err)
		}
		fmt.Printf("frame=%d kind=%d service=%d task=%d tx=%d flags=%d payload=%d hex=%s\n", index, frame.Kind, frame.Service, frame.Task, frame.Transaction, frame.Flags, len(frame.Payload), hex.EncodeToString(frame.Payload))
	}
}

func inspectJSONL(r io.Reader, max uint32) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16<<20)
	for scanner.Scan() {
		var record capture.Record
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			fatal(err)
		}
		payload, err := hex.DecodeString(record.Payload)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("%s %s %s %s bytes=%d sha256=%s\n", record.Timestamp.Format("2006-01-02T15:04:05Z"), record.Listener, record.Direction, record.Remote, record.Length, record.SHA256)
		inspectFrames(bytes.NewReader(payload), max)
	}
	if err := scanner.Err(); err != nil {
		fatal(err)
	}
}

func fatal(err error) { fmt.Fprintln(os.Stderr, "error:", err); os.Exit(1) }
