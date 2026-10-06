// Package proto decodes the link, network and transport headers carried
// by pcap frames. Decoders perform strict bounds checks: truncated or
// malformed bytes yield typed errors rather than panics.
package proto

import (
	"errors"
	"fmt"

	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
)

// Direction-neutral protocol numbers.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

var (
	// ErrShortFrame means the captured bytes ended before a complete header.
	ErrShortFrame = errors.New("proto: frame truncated")
	// ErrMalformed means a length/version/offset field was invalid.
	ErrMalformed = errors.New("proto: malformed header")
	// ErrUnsupported means the protocol/option set is not analyzed.
	ErrUnsupported = errors.New("proto: unsupported protocol")
)

// DecodeError wraps a decode failure with the layer at which it occurred.
type DecodeError struct {
	Layer  string
	Record int64
	Err    error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("proto: record #%d %s decode: %s", e.Record, e.Layer, e.Err)
}
func (e *DecodeError) Unwrap() error { return e.Err }

// Packet is one decoded transport packet (TCP or UDP).
type Packet struct {
	Record int64
	IP     IPHeader
	TCP    *TCPHeader
	UDP    *UDPHeader
	// Payload bytes (possibly truncated at snaplen).
	Payload []byte
	// SnapTruncated says capture truncation may have cut headers/payload.
	SnapTruncated bool
}

// IPHeader is protocol-version agnostic.
type IPHeader struct {
	Version  uint8
	Src      string
	Dst      string
	Protocol uint8
	SrcRaw   []byte
	DstRaw   []byte
}

// TCPHeader holds the fields needed for reassembly and behavior analysis.
type TCPHeader struct {
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
	Flags   TCPFlags
	Window  uint16
}

// TCPFlags as individual bits.
type TCPFlags uint8

const (
	TCPFin TCPFlags = 1 << 0
	TCPSyn TCPFlags = 1 << 1
	TCPRst TCPFlags = 1 << 2
	TCPPsh TCPFlags = 1 << 3
	TCPAck TCPFlags = 1 << 4
	TCPUrg TCPFlags = 1 << 5
)

func (f TCPFlags) Has(x TCPFlags) bool { return f&x != 0 }

func (f TCPFlags) String() string {
	const order = "FSRPAU"
	bits := []TCPFlags{TCPSyn, TCPFin, TCPRst, TCPPsh, TCPAck, TCPUrg}
	out := make([]byte, 0, 6)
	for i, b := range bits {
		if f&b != 0 {
			out = append(out, order[i])
		}
	}
	if len(out) == 0 {
		return "."
	}
	return string(out)
}

// UDPHeader holds port information (used for lightweight UDP flows).
type UDPHeader struct {
	SrcPort uint16
	DstPort uint16
	Length  uint16
}

// DecodeFrame decodes one captured record according to the capture link
// type. Non-TCP/UDP protocols return ErrUnsupported wrapped in DecodeError.
func DecodeFrame(link pcapio.LinkType, rec *pcapio.Record) (*Packet, error) {
	ipBytes, err := stripLink(link, rec.Data)
	if err != nil {
		return nil, &DecodeError{Layer: "link", Record: rec.Index, Err: err}
	}
	iph, l4, err := decodeIP(ipBytes)
	if err != nil {
		return nil, &DecodeError{Layer: "ip", Record: rec.Index, Err: err}
	}
	pk := &Packet{
		Record:        rec.Index,
		IP:            iph,
		Payload:       l4,
		SnapTruncated: rec.Truncated(),
	}
	switch iph.Protocol {
	case ProtoTCP:
		t, payload, err := decodeTCP(l4)
		if err != nil {
			return nil, &DecodeError{Layer: "tcp", Record: rec.Index, Err: err}
		}
		pk.TCP = t
		pk.Payload = payload
	case ProtoUDP:
		u, payload, err := decodeUDP(l4)
		if err != nil {
			return nil, &DecodeError{Layer: "udp", Record: rec.Index, Err: err}
		}
		pk.UDP = u
		pk.Payload = payload
	default:
		return nil, &DecodeError{Layer: "ip", Record: rec.Index,
			Err: fmt.Errorf("%w: protocol %d", ErrUnsupported, iph.Protocol)}
	}
	return pk, nil
}

func stripLink(link pcapio.LinkType, data []byte) ([]byte, error) {
	switch link {
	case pcapio.LinkEther:
		if len(data) < 14 {
			return nil, fmt.Errorf("%w: ethernet header", ErrShortFrame)
		}
		ethertype := uint16(data[12])<<8 | uint16(data[13])
		rest := data[14:]
		switch ethertype {
		case 0x0800, 0x86dd:
			return rest, nil
		case 0x8100: // 802.1Q VLAN
			if len(rest) < 4 {
				return nil, fmt.Errorf("%w: vlan tag", ErrShortFrame)
			}
			inner := uint16(rest[2])<<8 | uint16(rest[3])
			if inner != 0x0800 && inner != 0x86dd {
				return nil, fmt.Errorf("%w: ethertype %#04x", ErrUnsupported, inner)
			}
			return rest[4:], nil
		default:
			return nil, fmt.Errorf("%w: ethertype %#04x", ErrUnsupported, ethertype)
		}
	case pcapio.LinkRaw:
		return data, nil
	case pcapio.LinkNull:
		if len(data) < 4 {
			return nil, fmt.Errorf("%w: null header", ErrShortFrame)
		}
		// BSD loopback: 4-byte AF_INET(2)/AF_INET6(28 or 30).
		fam := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
		if fam == 0x02000000 { // big-endian 2
			fam = 2
		}
		if fam != 2 && fam != 28 && fam != 30 {
			return nil, fmt.Errorf("%w: loopback family %d", ErrUnsupported, fam)
		}
		return data[4:], nil
	case pcapio.LinkLinux:
		// Linux cooked capture v1: 16-byte header.
		if len(data) < 16 {
			return nil, fmt.Errorf("%w: cooked header", ErrShortFrame)
		}
		proto := uint16(data[14])<<8 | uint16(data[15])
		if proto != 0x0800 && proto != 0x86dd {
			return nil, fmt.Errorf("%w: cooked proto %#04x", ErrUnsupported, proto)
		}
		return data[16:], nil
	default:
		return nil, fmt.Errorf("%w: link %s", ErrUnsupported, link.String())
	}
}
