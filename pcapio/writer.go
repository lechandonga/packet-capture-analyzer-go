package pcapio

import (
	"encoding/binary"
	"io"
	"time"
)

// Writer emits classic little-endian pcap files (microsecond resolution).
// It exists so tests and tooling can build deterministic local captures
// without any external libraries or network access.
type Writer struct {
	w  io.Writer
	bo binary.ByteOrder
}

// NewWriter writes the global header for the given link type and snaplen.
func NewWriter(w io.Writer, link LinkType, snaplen uint32) (*Writer, error) {
	if !SupportedLink(link) {
		return nil, &FileError{Kind: ErrUnsupportedLink, Detail: link.String()}
	}
	if snaplen == 0 {
		snaplen = 65535
	}
	pw := &Writer{w: w, bo: binary.LittleEndian}
	hdr := make([]byte, 24)
	pw.bo.PutUint32(hdr[0:4], magicUS)
	pw.bo.PutUint16(hdr[4:6], 2)
	pw.bo.PutUint16(hdr[6:8], 4)
	pw.bo.PutUint32(hdr[16:20], snaplen)
	pw.bo.PutUint32(hdr[20:24], uint32(link))
	if _, err := w.Write(hdr); err != nil {
		return nil, err
	}
	return pw, nil
}

// WriteRecord appends one frame. When data is longer than snaplen it is
// truncated and origLen records the original (pre-cut) length, exactly as
// a real capture with snaplen would store it.
func (w *Writer) WriteRecord(ts time.Time, origLen uint32, data []byte) error {
	if origLen == 0 {
		origLen = uint32(len(data))
	}
	incl := uint32(len(data))
	if incl > origLen {
		incl = origLen
	}
	hdr := make([]byte, 16)
	sec := ts.Unix()
	w.bo.PutUint32(hdr[0:4], uint32(sec))
	w.bo.PutUint32(hdr[4:8], uint32(ts.Sub(time.Unix(sec, 0)).Microseconds()))
	w.bo.PutUint32(hdr[8:12], incl)
	w.bo.PutUint32(hdr[12:16], origLen)
	if _, err := w.w.Write(hdr); err != nil {
		return err
	}
	if incl > 0 {
		if _, err := w.w.Write(data[:incl]); err != nil {
			return err
		}
	}
	return nil
}
