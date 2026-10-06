// Package pcapgen builds deterministic in-memory pcap files and TCP/IP frames
// for tests. Nothing here touches a network interface.
package pcapgen

import (
	"encoding/binary"
)

// Builder accumulates frames and serializes classic pcap (little endian,
// Ethernet link type by default).
type Builder struct {
	LinkType uint16
	frames   []frame
	tsBase   uint32
	nextUsec uint32
}

type frame struct {
	sec, usec uint32
	data      []byte
}

// New returns an Ethernet builder.
func New() *Builder { return &Builder{LinkType: 1, tsBase: 1_700_000_000} }

// NewLink returns a builder for any link type (frames must already match).
func NewLink(link uint16) *Builder {
	b := New()
	b.LinkType = link
	return b
}

// Add appends a raw link-layer frame with a deterministic timestamp.
func (b *Builder) Add(data []byte) *Builder {
	off := b.nextUsec
	b.nextUsec += 1000
	return b.AddAt(off, data)
}

// AddAt appends a frame at an explicit microsecond offset from base.
func (b *Builder) AddAt(offsetUsec uint32, data []byte) *Builder {
	if offsetUsec >= b.nextUsec {
		b.nextUsec = offsetUsec + 1000
	}
	b.frames = append(b.frames, frame{sec: b.tsBase + offsetUsec/1_000_000, usec: offsetUsec % 1_000_000, data: append([]byte(nil), data...)})
	return b
}

// Frames returns the number of records added.
func (b *Builder) Frames() int { return len(b.frames) }

// Bytes serializes the full pcap file.
func (b *Builder) Bytes() []byte {
	out := make([]byte, 0, 24+len(b.frames)*40)
	hdr := []byte{
		0xa1, 0xb2, 0xc3, 0xd4, // libpcap magic: little-endian, microseconds
		0x02, 0x00, 0x04, 0x00, // 2.4
		0, 0, 0, 0, 0, 0, 0, 0, // thiszone, sigfigs
		0, 0, 0xff, 0xff, // snaplen
	}
	out = append(out, hdr...)
	lt := make([]byte, 4)
	binary.LittleEndian.PutUint32(lt, uint32(b.LinkType))
	out = append(out, lt...)
	for _, f := range b.frames {
		rh := make([]byte, 16)
		binary.LittleEndian.PutUint32(rh[0:], f.sec)
		binary.LittleEndian.PutUint32(rh[4:], f.usec)
		binary.LittleEndian.PutUint32(rh[8:], uint32(len(f.data)))
		binary.LittleEndian.PutUint32(rh[12:], uint32(len(f.data)))
		out = append(out, rh...)
		out = append(out, f.data...)
	}
	return out
}

// Truncate returns the file shortened to n bytes (corruption simulation).
func (b *Builder) Truncate(n int) []byte {
	full := b.Bytes()
	if n > len(full) {
		n = len(full)
	}
	return full[:n]
}

// WithHeader returns the serialized file with the global header patched.
func (b *Builder) WithHeader(patch func(hdr []byte)) []byte {
	full := b.Bytes()
	hdr := make([]byte, 24)
	copy(hdr, full[:24])
	patch(hdr)
	out := append(hdr, full[24:]...)
	return out
}

// --- Frame construction --------------------------------------------------

// IPv4 builds an IPv4 packet carrying TCP or UDP.
func IPv4(src, dst [4]byte, proto uint8, payload []byte) []byte {
	total := 20 + len(payload)
	out := make([]byte, total)
	out[0] = 0x45
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	binary.BigEndian.PutUint16(out[6:8], 0) // no fragmentation
	out[8] = 64
	out[9] = proto
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])
	copy(out[20:], payload)
	return out
}

// TCP builds a TCP segment.
func TCP(sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	out := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(out[0:2], sport)
	binary.BigEndian.PutUint16(out[2:4], dport)
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint32(out[8:12], ack)
	out[12] = 5 << 4 // data offset 20
	out[13] = flags
	binary.BigEndian.PutUint16(out[14:16], 64240)
	copy(out[20:], payload)
	return out
}

// UDP builds a UDP datagram.
func UDP(sport, dport uint16, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(out[0:2], sport)
	binary.BigEndian.PutUint16(out[2:4], dport)
	binary.BigEndian.PutUint16(out[4:6], uint16(8+len(payload)))
	copy(out[8:], payload)
	return out
}

// Ethernet wraps a payload in an Ethernet II frame for IPv4 (0x0800) or IPv6.
func Ethernet(src, dst [6]byte, etherType uint16, payload []byte) []byte {
	out := make([]byte, 14+len(payload))
	copy(out[0:6], dst[:])
	copy(out[6:12], src[:])
	binary.BigEndian.PutUint16(out[12:14], etherType)
	copy(out[14:], payload)
	return out
}

// EthIP4TCP is a one-call helper used heavily in tests.
func EthIP4TCP(macS, macD [6]byte, ipS, ipD [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return Ethernet(macS, macD, 0x0800, IPv4(ipS, ipD, 6, TCP(sport, dport, seq, ack, flags, payload)))
}

// RawIP4TCP produces a raw-IP (LINKTYPE_RAW style) frame.
func RawIP4TCP(ipS, ipD [4]byte, sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return IPv4(ipS, ipD, 6, TCP(sport, dport, seq, ack, flags, payload))
}

// Null wraps an IPv4 packet with the BSD loopback AF header.
func Null(ipPacket []byte) []byte {
	out := make([]byte, 4+len(ipPacket))
	binary.LittleEndian.PutUint32(out[0:4], 2) // AF_INET
	copy(out[4:], ipPacket)
	return out
}

// SLL wraps an IPv4 packet in a Linux cooked capture v1 frame.
func SLL(ipPacket []byte) []byte {
	out := make([]byte, 16+len(ipPacket))
	// packet type 0 (sent by us), ARPHRD 1, addr len 6
	out[14] = 0x08
	out[15] = 0x00
	copy(out[16:], ipPacket)
	return out
}
