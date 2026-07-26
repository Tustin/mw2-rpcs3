package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type Encoder struct {
	buf bytes.Buffer
}

func (e *Encoder) Uint8(value uint8)   { e.buf.WriteByte(value) }
func (e *Encoder) Uint16(value uint16) { _ = binary.Write(&e.buf, binary.BigEndian, value) }
func (e *Encoder) Uint32(value uint32) { _ = binary.Write(&e.buf, binary.BigEndian, value) }
func (e *Encoder) Uint64(value uint64) { _ = binary.Write(&e.buf, binary.BigEndian, value) }
func (e *Encoder) Bool(value bool) {
	if value {
		e.Uint8(1)
	} else {
		e.Uint8(0)
	}
}
func (e *Encoder) Bytes(value []byte) {
	e.Uint32(uint32(len(value)))
	e.buf.Write(value)
}
func (e *Encoder) String(value string) { e.Bytes([]byte(value)) }
func (e *Encoder) Data() []byte        { return append([]byte(nil), e.buf.Bytes()...) }

type Decoder struct {
	r        *bytes.Reader
	maxField uint32
}

func NewDecoder(data []byte, maxField uint32) *Decoder {
	return &Decoder{r: bytes.NewReader(data), maxField: maxField}
}

func (d *Decoder) Uint8() (uint8, error) { return d.r.ReadByte() }
func (d *Decoder) Uint16() (uint16, error) {
	var value uint16
	return value, binary.Read(d.r, binary.BigEndian, &value)
}
func (d *Decoder) Uint32() (uint32, error) {
	var value uint32
	return value, binary.Read(d.r, binary.BigEndian, &value)
}
func (d *Decoder) Uint64() (uint64, error) {
	var value uint64
	return value, binary.Read(d.r, binary.BigEndian, &value)
}
func (d *Decoder) Bool() (bool, error) {
	value, err := d.Uint8()
	if err != nil {
		return false, err
	}
	if value > 1 {
		return false, fmt.Errorf("invalid bool %d", value)
	}
	return value == 1, nil
}
func (d *Decoder) Bytes() ([]byte, error) {
	size, err := d.Uint32()
	if err != nil {
		return nil, err
	}
	if size > d.maxField || uint64(size) > uint64(d.r.Len()) {
		return nil, fmt.Errorf("invalid field size %d", size)
	}
	value := make([]byte, size)
	_, err = io.ReadFull(d.r, value)
	return value, err
}
func (d *Decoder) String() (string, error) {
	value, err := d.Bytes()
	return string(value), err
}
func (d *Decoder) Remaining() int { return d.r.Len() }
