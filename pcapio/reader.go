// Package pcapio reads classic libpcap capture files (RFC-style common
// format, little and big endian) entirely from local files or streams.
// It never opens network interfaces and requires no capture privileges.
//
// Corrupt files or records are reported through distinguishable, typed
// errors instead of panics or silent drops. A Reader fails the single
// capture it processes; batch processing in ProcessFiles isolates each
// file so one bad file never affects the others.
package pcapio

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

// LinkType identifies the data link layer of a capture.
type LinkType uint32

const (
	LinkNull  LinkType = 0   // BSD loopback
	LinkEther LinkType = 1   // Ethernet
	LinkRaw   LinkType = 12  // raw IPv4/IPv6 (DLT_RAW)
	LinkLinux LinkType = 113 // Linux cooked capture v1
)

// String returns a short human-readable name.
func (l LinkType) String() string {
	switch l {
	case LinkNull:
		return "NULL/Loopback"
	case LinkEther:
		return "Ethernet"
	case LinkRaw:
		return "Raw IP"
	case LinkLinux:
		return "Linux cooked v1"
	default:
		return fmt.Sprintf("Unknown(%d)", uint32(l))
	}
}

// Record is one captured frame plus its timestamp.
type Record struct {
	TS      time.Time
	InclLen uint32
	OrigLen uint32
	Data    []byte
	Index   int64 // zero-based position of the record within the capture
}

// Truncated reports whether the frame was cut at capture time (snaplen).
func (r *Record) Truncated() bool { return r.OrigLen > r.InclLen }

// Magic numbers used to detect byte order and timestamp resolution.
const (
	magicUS = 0xa1b2c3d4 // microsecond resolution
	magicNS = 0xa1b23c4d // nanosecond resolution
)

// GlobalHeader is the 24-byte pcap global header.
type GlobalHeader struct {
	Magic        uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      LinkType
}

// Reader streams records from one classic pcap source.
type Reader struct {
	r       io.Reader
	hdr     GlobalHeader
	bo      binary.ByteOrder
	nano    bool
	index   int64
	started bool
}

// NewReader parses the global header and returns a streaming record reader.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReader(r)
	rd := &Reader{r: br}
	if err := rd.readGlobalHeader(); err != nil {
		return nil, err
	}
	return rd, nil
}

// Header returns the parsed global header.
func (r *Reader) Header() GlobalHeader { return r.hdr }

// Link returns the capture link-layer type.
func (r *Reader) Link() LinkType { return r.hdr.Network }

func (r *Reader) readGlobalHeader() error {
	var mb [4]byte
	if _, err := io.ReadFull(r.r, mb[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return &FileError{Kind: ErrTruncatedFile, Err: io.ErrUnexpectedEOF}
		}
		return &FileError{Kind: ErrIOFailure, Err: err}
	}
	switch binary.LittleEndian.Uint32(mb[:]) {
	case magicUS:
		r.bo = binary.LittleEndian
	case magicNS:
		r.bo = binary.LittleEndian
		r.nano = true
	default:
		switch binary.BigEndian.Uint32(mb[:]) {
		case magicUS:
			r.bo = binary.BigEndian
		case magicNS:
			r.bo = binary.BigEndian
			r.nano = true
		default:
			return &FileError{Kind: ErrBadMagic, Detail: fmt.Sprintf("%#08x", binary.LittleEndian.Uint32(mb[:]))}
		}
	}

	rest := make([]byte, 20)
	if _, err := io.ReadFull(r.r, rest); err != nil {
		return &FileError{Kind: ErrTruncatedFile, Err: err}
	}
	r.hdr.Magic = r.bo.Uint32(mb[:])
	r.hdr.VersionMajor = r.bo.Uint16(rest[0:2])
	r.hdr.VersionMinor = r.bo.Uint16(rest[2:4])
	r.hdr.Thiszone = int32(r.bo.Uint32(rest[4:8]))
	r.hdr.Sigfigs = r.bo.Uint32(rest[8:12])
	r.hdr.Snaplen = r.bo.Uint32(rest[12:16])           // bytes 16:20 of full header
	r.hdr.Network = LinkType(r.bo.Uint32(rest[16:20])) // bytes 20:24

	if r.hdr.VersionMajor != 2 || r.hdr.VersionMinor != 4 {
		return &FileError{
			Kind:   ErrUnsupportedVersion,
			Detail: fmt.Sprintf("%d.%d", r.hdr.VersionMajor, r.hdr.VersionMinor),
		}
	}
	if !SupportedLink(r.hdr.Network) {
		return &FileError{Kind: ErrUnsupportedLink, Detail: r.hdr.Network.String()}
	}
	r.started = true
	return nil
}

// Next returns the next record or io.EOF when the capture ended cleanly.
// Damaged records are returned as *RecordError wrapping io.EOF ends the
// stream; callers can decide to stop or (via ReadAll) collect the issue.
func (r *Reader) Next() (*Record, error) {
	if !r.started {
		return nil, errors.New("pcapio: reader not initialized")
	}
	hdr := make([]byte, 16)
	n, err := io.ReadFull(r.r, hdr)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &FileError{Kind: ErrTruncatedFile, Err: fmt.Errorf("%d-byte partial record header", n)}
		}
		return nil, &FileError{Kind: ErrIOFailure, Err: err}
	}

	sec := r.bo.Uint32(hdr[0:4])
	frac := r.bo.Uint32(hdr[4:8])
	incl := r.bo.Uint32(hdr[8:12])
	orig := r.bo.Uint32(hdr[12:16])

	if incl == 0 && orig == 0 {
		rec := &Record{TS: stamp(sec, frac, r.nano), Index: r.index}
		r.index++
		return rec, nil
	}
	if incl == 0 || orig == 0 {
		return nil, &RecordError{Index: r.index, Kind: ErrBadRecordLength,
			Detail: fmt.Sprintf("incl=%d orig=%d", incl, orig)}
	}
	if incl > orig {
		// Stream alignment is lost: incl is the byte count the parser
		// must consume, so an incl larger than orig makes remaining
		// records unlocatable. Report it as a fatal file-level error.
		return nil, &FileError{Kind: ErrTruncatedFile,
			Detail: fmt.Sprintf("record #%d: %s incl=%d orig=%d",
				r.index, ErrInclExceedsOrig, incl, orig)}
	}
	if r.hdr.Snaplen != 0 && incl > r.hdr.Snaplen {
		return nil, &RecordError{Index: r.index, Kind: ErrRecordBeyondSnap,
			Detail: fmt.Sprintf("incl=%d snaplen=%d", incl, r.hdr.Snaplen)}
	}

	data := make([]byte, incl)
	if _, err := io.ReadFull(r.r, data); err != nil {
		return nil, &RecordError{Index: r.index, Kind: ErrTruncatedRecord, Err: err}
	}

	rec := &Record{
		TS:      stamp(sec, frac, r.nano),
		InclLen: incl,
		OrigLen: orig,
		Data:    data,
		Index:   r.index,
	}
	r.index++
	return rec, nil
}

func stamp(sec, frac uint32, nano bool) time.Time {
	if nano {
		return time.Unix(int64(sec), int64(frac)).UTC()
	}
	return time.Unix(int64(sec), int64(frac)*int64(time.Microsecond)).UTC()
}

// SupportedLink reports whether the engine understands a link type.
func SupportedLink(l LinkType) bool {
	switch l {
	case LinkNull, LinkEther, LinkRaw, LinkLinux:
		return true
	default:
		return false
	}
}

// Capture is the deterministic result of parsing one pcap source.
type Capture struct {
	Header  GlobalHeader
	Records []*Record
}

// ReadAll consumes the whole capture. Malformed records are collected in
// RecordErrs (nothing is silently skipped); a fatal file-level error is
// returned together with the records already read.
func ReadAll(r io.Reader) (*Capture, []*RecordError, error) {
	rd, err := NewReader(r)
	if err != nil {
		return nil, nil, err
	}
	cap := &Capture{Header: rd.hdr}
	var recErrs []*RecordError
	for {
		rec, err := rd.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			var re *RecordError
			if errors.As(err, &re) {
				recErrs = append(recErrs, re)
				continue
			}
			return cap, recErrs, err
		}
		cap.Records = append(cap.Records, rec)
	}
	return cap, recErrs, nil
}
