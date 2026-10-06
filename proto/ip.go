package proto

import (
	"fmt"
	"net/netip"
)

func decodeIP(b []byte) (IPHeader, []byte, error) {
	if len(b) < 1 {
		return IPHeader{}, nil, fmt.Errorf("%w: ip header", ErrShortFrame)
	}
	ver := b[0] >> 4
	switch ver {
	case 4:
		return decodeIPv4(b)
	case 6:
		return decodeIPv6(b)
	default:
		return IPHeader{}, nil, fmt.Errorf("%w: ip version %d", ErrUnsupported, ver)
	}
}

func decodeIPv4(b []byte) (IPHeader, []byte, error) {
	if len(b) < 20 {
		return IPHeader{}, nil, fmt.Errorf("%w: ipv4 header", ErrShortFrame)
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 {
		return IPHeader{}, nil, fmt.Errorf("%w: ihl=%d bytes", ErrMalformed, ihl)
	}
	if len(b) < ihl {
		return IPHeader{}, nil, fmt.Errorf("%w: ipv4 options", ErrShortFrame)
	}
	totalLen := int(b[2])<<8 | int(b[3])
	if totalLen != 0 && totalLen < ihl {
		return IPHeader{}, nil, fmt.Errorf("%w: total length %d < ihl %d", ErrMalformed, totalLen, ihl)
	}
	l4 := b[ihl:]
	if totalLen != 0 && totalLen-ihl <= len(l4) {
		l4 = l4[:totalLen-ihl]
	}
	h := IPHeader{
		Version:  4,
		Src:      netip.AddrFrom4([4]byte(b[12:16])).String(),
		Dst:      netip.AddrFrom4([4]byte(b[16:20])).String(),
		Protocol: b[9],
		SrcRaw:   append([]byte(nil), b[12:16]...),
		DstRaw:   append([]byte(nil), b[16:20]...),
	}
	return h, l4, nil
}

func decodeIPv6(b []byte) (IPHeader, []byte, error) {
	if len(b) < 40 {
		return IPHeader{}, nil, fmt.Errorf("%w: ipv6 header", ErrShortFrame)
	}
	// Only the basic header is supported; extension headers are not
	// traversed (reported as unsupported) to keep reassembly semantics
	// explicit rather than guessing next-header chains.
	proto := b[6]
	if proto != ProtoTCP && proto != ProtoUDP {
		return IPHeader{}, nil, fmt.Errorf("%w: ipv6 next-header %d", ErrUnsupported, proto)
	}
	payloadLen := int(b[4])<<8 | int(b[5])
	l4 := b[40:]
	if payloadLen <= len(l4) {
		l4 = l4[:payloadLen]
	}
	var src, dst [16]byte
	copy(src[:], b[8:24])
	copy(dst[:], b[24:40])
	h := IPHeader{
		Version:  6,
		Src:      netip.AddrFrom16(src).String(),
		Dst:      netip.AddrFrom16(dst).String(),
		Protocol: proto,
		SrcRaw:   append([]byte(nil), src[:]...),
		DstRaw:   append([]byte(nil), dst[:]...),
	}
	return h, l4, nil
}
