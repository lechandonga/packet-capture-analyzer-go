// Package pcaptest builds deterministic in-memory pcap captures for
// tests, with no external dependencies or network access.
package pcaptest

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
)

// TCP flag helpers.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// Frame is one synthetic record.
type Frame struct {
	TS      time.Time
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   uint8
	Payload []byte
	Bad     BadKind
}

// BadKind corrupts a frame at the capture-record layer.
type BadKind int

const (
	BadNone BadKind = iota
	BadTruncatedRecord
	BadInclOverOrig
)

// Build serializes frames as one little-endian Ethernet pcap blob.
func Build(link pcapio.LinkType, snaplen uint32, frames []Frame, rawSuffix []byte) []byte {
	var hdr bytes.Buffer
	w, err := pcapio.NewWriter(&hdr, link, snaplen)
	if err != nil {
		panic(err)
	}
	_ = w
	var out bytes.Buffer
	out.Write(hdr.Bytes())
	bo := binary.LittleEndian
	ts0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, f := range frames {
		ts := f.TS
		if ts.IsZero() {
			ts = ts0.Add(time.Duration(i) * time.Second)
		}
		pkt := EthernetIPv4TCP(f)
		orig := uint32(len(pkt))
		data := pkt
		if snaplen > 0 && uint32(len(data)) > snaplen {
			data = data[:snaplen]
		}
		rh := make([]byte, 16)
		bo.PutUint32(rh[0:4], uint32(ts.Unix()))
		bo.PutUint32(rh[4:8], uint32(ts.Sub(time.Unix(ts.Unix(), 0)).Microseconds()))
		switch f.Bad {
		case BadTruncatedRecord:
			bo.PutUint32(rh[8:12], orig)
			bo.PutUint32(rh[12:16], orig)
			out.Write(rh)
			out.Write(data[:len(data)-4])
		case BadInclOverOrig:
			bo.PutUint32(rh[8:12], orig+10)
			bo.PutUint32(rh[12:16], orig)
			out.Write(rh)
			out.Write(data)
		default:
			bo.PutUint32(rh[8:12], uint32(len(data)))
			bo.PutUint32(rh[12:16], orig)
			out.Write(rh)
			out.Write(data)
		}
	}
	if rawSuffix != nil {
		out.Write(rawSuffix)
	}
	return out.Bytes()
}

// EthernetIPv4TCP builds an Ethernet+IPv4+TCP frame for f.
func EthernetIPv4TCP(f Frame) []byte {
	tcp := buildTCP(f)
	src := netip.MustParseAddr(f.SrcIP).As4()
	dst := netip.MustParseAddr(f.DstIP).As4()
	ipTotal := 20 + len(tcp)
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[2] = byte(ipTotal >> 8)
	ip[3] = byte(ipTotal)
	ip[6] = 0x40
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	csum(ip)
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	return append(append(eth, ip...), tcp...)
}

func buildTCP(f Frame) []byte {
	tcp := make([]byte, 20+len(f.Payload))
	binary.BigEndian.PutUint16(tcp[0:2], f.SrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], f.DstPort)
	binary.BigEndian.PutUint32(tcp[4:8], f.Seq)
	binary.BigEndian.PutUint32(tcp[8:12], f.Ack)
	tcp[12] = 5 << 4
	tcp[13] = f.Flags
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	copy(tcp[20:], f.Payload)
	csumTCP(tcp, f)
	return tcp
}

func csum(b []byte) {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	b[10] = byte(c >> 8)
	b[11] = byte(c)
}

func csumTCP(tcp []byte, f Frame) {
	src := netip.MustParseAddr(f.SrcIP).As4()
	dst := netip.MustParseAddr(f.DstIP).As4()
	sum := uint32(6 + len(tcp))
	for _, b := range src {
		sum += uint32(b)
	}
	for _, b := range dst {
		sum += uint32(b)
	}
	tcp[16], tcp[17] = 0, 0
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	c := ^uint16(sum)
	tcp[16] = byte(c >> 8)
	tcp[17] = byte(c)
}
