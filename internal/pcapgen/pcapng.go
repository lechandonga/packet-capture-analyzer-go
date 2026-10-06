package pcapgen

import "encoding/binary"

// PCAPNGBuilder serializes a minimal big-endian pcapng file: one SHB, one IDB
// and one EPB per frame.
type PCAPNGBuilder struct {
	LinkType uint16
	frames   [][]byte
}

// NewNG returns a pcapng builder with Ethernet link type.
func NewNG() *PCAPNGBuilder { return &PCAPNGBuilder{LinkType: 1} }

// Add stores one raw frame.
func (b *PCAPNGBuilder) Add(frame []byte) *PCAPNGBuilder {
	b.frames = append(b.frames, append([]byte(nil), frame...))
	return b
}

func put32be(out []byte, off int, v uint32) { binary.BigEndian.PutUint32(out[off:], v) }
func put16be(out []byte, off int, v uint16) { binary.BigEndian.PutUint16(out[off:], v) }

// Bytes serializes the file.
func (b *PCAPNGBuilder) Bytes() []byte {
	var out []byte
	w32 := func(v uint32) { buf := make([]byte, 4); binary.BigEndian.PutUint32(buf, v); out = append(out, buf...) }
	w16 := func(v uint16) { buf := make([]byte, 2); binary.BigEndian.PutUint16(buf, v); out = append(out, buf...) }

	// SHB, total 28 bytes (no options).
	w32(0x0A0D0D0A)
	w32(28)
	w32(0x1A2B3C4D)
	w16(1)
	w16(0)
	w32(0xffffffff)
	w32(0xffffffff)
	w32(28)

	// IDB, total 24 bytes: 8 header + 8 fixed fields + 4 options + 4 trailer.
	w32(1)
	w32(24)
	w16(b.LinkType)
	w16(0)
	w32(65535)
	w32(0) // no options
	w32(24)

	for i, frame := range b.frames {
		paddedLen := (len(frame) + 3) &^ 3
		total := uint32(12 + 20 + paddedLen)
		w32(6)
		w32(total)
		w32(0) // interface id
		ts := uint64(1_700_000_000_000_000) + uint64(i)*1000
		w32(uint32(ts >> 32))
		w32(uint32(ts))
		w32(uint32(len(frame)))
		w32(uint32(len(frame)))
		padded := make([]byte, paddedLen)
		copy(padded, frame)
		out = append(out, padded...)
		w32(total)
	}
	_ = put32be
	_ = put16be
	return out
}
