package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const HeaderSize = 12

const (
	KindRequest  uint8 = 1
	KindResponse uint8 = 2
	KindError    uint8 = 3
)

var (
	ErrFrameTooLarge = errors.New("frame exceeds configured limit")
	ErrInvalidFrame  = errors.New("invalid frame")
)

type Frame struct {
	Kind        uint8
	Service     uint8
	Task        uint8
	Flags       uint8
	Transaction uint32
	Payload     []byte
}

func ReadFrame(r io.Reader, maxPayload uint32) (Frame, error) {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	payloadSize := binary.BigEndian.Uint32(header[8:12])
	if payloadSize > maxPayload {
		return Frame{}, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, payloadSize, maxPayload)
	}
	if header[0] < KindRequest || header[0] > KindError {
		return Frame{}, fmt.Errorf("%w: unknown kind %d", ErrInvalidFrame, header[0])
	}
	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{
		Kind:        header[0],
		Service:     header[1],
		Task:        header[2],
		Flags:       header[3],
		Transaction: binary.BigEndian.Uint32(header[4:8]),
		Payload:     payload,
	}, nil
}

func MarshalFrame(frame Frame, maxPayload uint32) ([]byte, error) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, frame, maxPayload); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func WriteFrame(w io.Writer, frame Frame, maxPayload uint32) error {
	if uint64(len(frame.Payload)) > uint64(maxPayload) {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(frame.Payload), maxPayload)
	}
	if frame.Kind < KindRequest || frame.Kind > KindError {
		return fmt.Errorf("%w: unknown kind %d", ErrInvalidFrame, frame.Kind)
	}
	header := make([]byte, HeaderSize)
	header[0] = frame.Kind
	header[1] = frame.Service
	header[2] = frame.Task
	header[3] = frame.Flags
	binary.BigEndian.PutUint32(header[4:8], frame.Transaction)
	binary.BigEndian.PutUint32(header[8:12], uint32(len(frame.Payload)))
	if _, err := w.Write(header); err != nil {
		return err
	}
	_, err := w.Write(frame.Payload)
	return err
}
