package pcap

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// LinkType is a LINKTYPE_* value as stored in a capture file.
type LinkType uint16

// Link types decoded by this package.
const (
	LinkEthernet  LinkType = 1
	LinkNull      LinkType = 0 // BSD loopback, 4-byte AF header
	LinkRaw       LinkType = 101
	LinkLinuxSLL  LinkType = 113
	LinkLinuxSLL2 LinkType = 276
)

// Format identifies the on-disk capture container.
type Format int

const (
	FormatUnknown Format = iota
	FormatPCAP
	FormatPCAPNG
)

func (f Format) String() string {
	switch f {
	case FormatPCAP:
		return "pcap"
	case FormatPCAPNG:
		return "pcapng"
	default:
		return "unknown"
	}
}

// Packet is one decoded record from a capture file.
type Packet struct {
	// Index is the zero-based ordinal of the packet record in the file.
	Index int
	// Ts is the capture timestamp; zero when unavailable.
	TS
	// Link is the record's link type.
	Link LinkType
	// Data points at the packet layer (TCP/UDP payload) and is nil when the
	// packet was skipped.
	IP
	// RawLen is the original on-wire length (orig_len).
	RawLen uint32
	// CapLen is the number of bytes actually stored (incl_len).
	CapLen uint32
}

// TS is a microsecond-resolution capture timestamp.
type TS struct {
	Sec  int64
	Usec int64
}

// IP holds the decoded network/transport content.
type IP struct {
	Version  uint8 // 4 or 6
	SrcIP    [16]byte
	DstIP    [16]byte
	SrcIPLen int // 4 for IPv4, 16 for IPv6
	DstIPLen int
	Proto    uint8 // 6 = TCP, 17 = UDP
	TCP      *TCPHeader
	UDP      *UDPHeader
	// Payload is the transport payload; it aliases the reader's scratch
	// buffer and must be copied if retained beyond the next Read call.
	Payload []byte
}

// Src returns the source address in canonical 4- or 16-byte form.
func (p IP) Src() []byte { return p.SrcIP[:p.SrcIPLen] }

// Dst returns the destination address in canonical 4- or 16-byte form.
func (p IP) Dst() []byte { return p.DstIP[:p.DstIPLen] }

// TCPHeader is the fixed 20-byte TCP header plus flags.
type TCPHeader struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	DataOff uint8 // header length in bytes
	Flags   uint8
	Window  uint16
}

// TCP flag bits.
const (
	TCPFin = 0x01
	TCPSyn = 0x02
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPAck = 0x10
	TCPUrg = 0x20
)

// UDPHeader is the 8-byte UDP header.
type UDPHeader struct {
	SrcPort uint16
	DstPort uint16
}

// Stats summarises a read pass.
type Stats struct {
	Format      Format
	Link        LinkType
	Packets     int // number of data records seen
	Decoded     int // number of records decoded to transport payload
	Skipped     int // records skipped for a classified, non-fatal reason
	SkipReasons map[ErrorKind]int
}

// Reader streams packets from one capture file. A Reader is not safe for
// concurrent use; parse the same file with separate Readers instead.
type Reader struct {
	br    *bufio.Reader
	buf   []byte // reusable scratch buffer
	stats Stats

	format Format
	be     binary.ByteOrder // pcap: header byte order
	order  binary.ByteOrder // pcapng: per-reader byte order
	nano   bool             // pcap: nanosecond timestamps
	link   LinkType

	// pcapng state
	ifaces []ngIface
}

type ngIface struct {
	link    LinkType
	tsResol byte  // if_tsresol option value; defaults to 6
	tsOff   int64 // if_tsoffset option value
	snap    uint32
}

// NewReader prepares a Reader. The capture header is consumed eagerly so that
// header-level errors are returned before the first packet.
func NewReader(r io.Reader) (*Reader, error) {
	rd := &Reader{
		br: bufio.NewReaderSize(r, 64*1024),
	}
	magic, err := rd.readMagic()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errf(KindTruncatedHeader, -1, "file is empty")
		}
		return nil, errf(KindTruncatedHeader, -1, "cannot read magic: %v", err)
	}
	switch {
	case magic[0] == 0x0a && magic[1] == 0x0d && magic[2] == 0x0d && magic[3] == 0x0a:
		rd.format = FormatPCAPNG
		rd.stats.Format = FormatPCAPNG
		if err := rd.readNGHeader(); err != nil {
			return nil, err
		}
	case magic[0] == 0xd4 && magic[1] == 0xc3 && magic[2] == 0xb2 && magic[3] == 0xa1:
		rd.be, rd.nano = binary.BigEndian, false
		if err := rd.readPcapHeader(); err != nil {
			return nil, err
		}
	case magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0xc3 && magic[3] == 0xd4:
		rd.be, rd.nano = binary.LittleEndian, false
		if err := rd.readPcapHeader(); err != nil {
			return nil, err
		}
	case magic[0] == 0x4d && magic[1] == 0x3c && magic[2] == 0xb2 && magic[3] == 0xa1:
		rd.be, rd.nano = binary.BigEndian, true
		if err := rd.readPcapHeader(); err != nil {
			return nil, err
		}
	case magic[0] == 0xa1 && magic[1] == 0xb2 && magic[2] == 0x3c && magic[3] == 0x4d:
		rd.be, rd.nano = binary.LittleEndian, true
		if err := rd.readPcapHeader(); err != nil {
			return nil, err
		}
	default:
		return nil, errf(KindBadMagic, -1, "magic bytes % x are neither pcap nor pcapng", magic)
	}
	return rd, nil
}

func (r *Reader) readPcapHeader() error {
	r.format = FormatPCAP
	r.stats.Format = FormatPCAP
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(r.br, hdr); err != nil {
		return errf(KindTruncatedHeader, -1, "global header: %v", err)
	}
	major := r.be.Uint16(hdr[0:2])
	minor := r.be.Uint16(hdr[2:4])
	if major != 2 || minor != 4 {
		return errf(KindUnsupportedVersion, -1, "pcap version %d.%d not supported (only 2.4)", major, minor)
	}
	r.link = LinkType(r.be.Uint32(hdr[16:20]))
	r.stats.Link = r.link
	if !supportedLink(r.link) {
		return errf(KindUnsupportedLinkType, -1, "link type %d is not supported", r.link)
	}
	return nil
}

// Link reports the capture link type.
func (r *Reader) Link() LinkType { return r.link }

// Format reports the detected container.
func (r *Reader) Format() Format { return r.format }

// Stats returns running read statistics.
func (r *Reader) Stats() Stats {
	s := r.stats
	s.SkipReasons = make(map[ErrorKind]int, len(r.stats.SkipReasons))
	for k, v := range r.stats.SkipReasons {
		s.SkipReasons[k] = v
	}
	return s
}

func supportedLink(l LinkType) bool {
	switch l {
	case LinkEthernet, LinkNull, LinkRaw, LinkLinuxSLL, LinkLinuxSLL2:
		return true
	}
	return false
}

// Read returns the next packet. A skipped record is reported via Stats, not as
// an error. io.EOF marks a clean end of file. File corruption returns a
// *ParseError; after such an error further Read calls return the same error.
func (r *Reader) Read() (*Packet, error) {
	for {
		var rec []byte
		var ts TS
		var link LinkType
		var capLen, rawLen uint32
		var err error
		if r.format == FormatPCAP {
			rec, ts, link, capLen, rawLen, err = r.readPcapRecord()
		} else {
			rec, ts, link, capLen, rawLen, err = r.readNGRecord()
		}
		if err != nil {
			return nil, err
		}
		if rec == nil {
			continue // non-packet block (pcapng) or skipped interface-less area
		}
		r.stats.Packets++
		pkt := &Packet{
			Index:  r.stats.Packets - 1,
			TS:     ts,
			Link:   link,
			RawLen: rawLen,
			CapLen: capLen,
		}
		if perr := decode(pkt, rec); perr != nil {
			// All per-packet decode classifications (snaplen truncation,
			// malformed frames, fragments, unsupported protocols) are
			// counted, non-fatal and never abort the rest of the file.
			r.recordSkip(perr.Kind)
			continue
		}
		r.stats.Decoded++
		return pkt, nil
	}
}

func (r *Reader) recordSkip(k ErrorKind) {
	if r.stats.SkipReasons == nil {
		r.stats.SkipReasons = map[ErrorKind]int{}
	}
	r.stats.SkipReasons[k]++
	r.stats.Skipped++
}

func (r *Reader) readPcapRecord() ([]byte, TS, LinkType, uint32, uint32, error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(r.br, hdr); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, TS{}, 0, 0, 0, io.EOF
		}
		return nil, TS{}, 0, 0, 0, errf(KindTruncatedHeader, r.stats.Packets, "record header: %v", err)
	}
	sec := int64(r.be.Uint32(hdr[0:4]))
	sub := int64(r.be.Uint32(hdr[4:8]))
	capLen := r.be.Uint32(hdr[8:12])
	rawLen := r.be.Uint32(hdr[12:16])
	if capLen > 64*1024*1024 || rawLen > 64*1024*1024 {
		return nil, TS{}, 0, 0, 0, errf(KindBadRecord, r.stats.Packets, "implausible incl_len=%d orig_len=%d", capLen, rawLen)
	}
	rec := make([]byte, capLen)
	if _, err := io.ReadFull(r.br, rec); err != nil {
		return nil, TS{}, 0, 0, 0, errf(KindTruncatedPacket, r.stats.Packets, "want %d captured bytes: %v", capLen, err)
	}
	ts := makeTS(sec, sub, r.nano)
	return rec, ts, r.link, capLen, rawLen, nil
}

func makeTS(sec, sub int64, nano bool) TS {
	if nano {
		return TS{Sec: sec, Usec: sub / 1000}
	}
	return TS{Sec: sec, Usec: sub}
}

func (r *Reader) ensureBuf(n int) []byte {
	if cap(r.buf) < n {
		r.buf = make([]byte, n)
	}
	return r.buf[:n]
}

// readN reads exactly n bytes; the returned slice may be overwritten by a
// later read and is only valid for small header probes.
func (r *Reader) readMagic() ([]byte, error) {
	b := make([]byte, 4)
	_, err := io.ReadFull(r.br, b)
	return b, err
}
