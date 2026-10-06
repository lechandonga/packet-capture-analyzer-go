// Package pcap reads locally saved packet-capture files (classic pcap and
// pcapng) without requiring any network interface or capture privilege.
//
// All failures are reported through typed errors with a stable ErrorKind so
// that callers can distinguish a truncated capture header, a truncated
// per-packet record, an unsupported version and an unsupported link type.
package pcap

import (
	"fmt"
)

// ErrorKind is a stable, machine-readable classification of a parse failure.
type ErrorKind string

const (
	// KindTruncatedHeader means the file (or a pcapng block) ended before a
	// fixed-size header could be read.
	KindTruncatedHeader ErrorKind = "truncated_header"
	// KindBadMagic means the global header magic is not a recognised pcap or
	// pcapng byte-order magic.
	KindBadMagic ErrorKind = "bad_magic"
	// KindUnsupportedVersion means the capture advertises a major/minor
	// version this reader does not implement.
	KindUnsupportedVersion ErrorKind = "unsupported_version"
	// KindUnsupportedLinkType means the capture's link layer is not decoded.
	KindUnsupportedLinkType ErrorKind = "unsupported_link_type"
	// KindBadRecord means a per-packet record contains an illegal length
	// (for example an absurd incl_len that cannot match the file).
	KindBadRecord ErrorKind = "bad_record"
	// KindTruncatedPacket means a record's incl_len bytes could not all be
	// read because the file ended early.
	KindTruncatedPacket ErrorKind = "truncated_packet"
	// KindCorrupt means a structural invariant is violated (for example a
	// pcapng block length is invalid or an unknown interface is referenced).
	KindCorrupt ErrorKind = "corrupt_file"
	// KindDecodeTruncated means an on-the-wire packet is shorter than its
	// declared headers (snaplen truncation or a malformed frame).
	KindDecodeTruncated ErrorKind = "packet_decode_truncated"
	// KindIPFragment means an IPv4/IPv6 non-first fragment was encountered;
	// fragment reassembly is intentionally not performed.
	KindIPFragment ErrorKind = "ip_fragment_skipped"
	// KindUnsupportedEtherType means the frame carries a network protocol
	// other than IPv4/IPv6 (ARP, MPLS, ...).
	KindUnsupportedEtherType ErrorKind = "unsupported_ethertype"
	// KindUnsupportedProtocol means the network packet is neither TCP nor UDP.
	KindUnsupportedProtocol ErrorKind = "unsupported_protocol"
)

// ParseError describes one classified failure. Index is the zero-based packet
// record index for per-packet errors, or -1 for file-level errors.
type ParseError struct {
	Kind  ErrorKind
	Index int
	Msg   string
}

func (e *ParseError) Error() string {
	if e.Index >= 0 {
		return fmt.Sprintf("pcap: %s (record %d): %s", e.Kind, e.Index, e.Msg)
	}
	return fmt.Sprintf("pcap: %s: %s", e.Kind, e.Msg)
}

func errf(kind ErrorKind, index int, format string, args ...any) *ParseError {
	return &ParseError{Kind: kind, Index: index, Msg: fmt.Sprintf(format, args...)}
}
