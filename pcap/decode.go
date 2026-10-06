package pcap

import (
	"encoding/binary"
)

// decode turns one raw captured frame into the packet's network/transport
// content. Non-fatal classifications (fragments, unsupported ethertypes and
// protocols, snaplen-truncated frames) are returned as *ParseError; the reader
// counts them and continues with the next record.
func decode(pkt *Packet, frame []byte) *ParseError {
	var ipData []byte
	var err *ParseError
	switch pkt.Link {
	case LinkEthernet:
		ipData, err = decodeEthernet(frame)
	case LinkNull:
		ipData, err = decodeNull(frame)
	case LinkRaw:
		ipData = frame
	case LinkLinuxSLL:
		ipData, err = decodeSLL(frame)
	case LinkLinuxSLL2:
		ipData, err = decodeSLL2(frame)
	default:
		return errf(KindUnsupportedLinkType, pkt.Index, "link type %d", pkt.Link)
	}
	if err != nil {
		err.Index = pkt.Index
		return err
	}
	if len(ipData) == 0 {
		return errf(KindDecodeTruncated, pkt.Index, "empty network-layer packet")
	}
	switch ipData[0] >> 4 {
	case 4:
		return decodeIPv4(pkt, ipData)
	case 6:
		return decodeIPv6(pkt, ipData)
	default:
		return errf(KindDecodeTruncated, pkt.Index, "unknown IP version %d", ipData[0]>>4)
	}
}

func decodeEthernet(frame []byte) ([]byte, *ParseError) {
	if len(frame) < 14 {
		return nil, errf(KindDecodeTruncated, 0, "ethernet frame shorter than 14 bytes (%d)", len(frame))
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[14:]
	// Strip a single 802.1Q VLAN tag (0x8100), plus QinQ (0x88a8/0x9100).
	for etherType == 0x8100 || etherType == 0x88a8 || etherType == 0x9100 {
		if len(payload) < 4 {
			return nil, errf(KindDecodeTruncated, 0, "truncated VLAN tag")
		}
		etherType = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	switch etherType {
	case 0x0800, 0x86dd:
		return payload, nil
	default:
		return nil, errf(KindUnsupportedEtherType, 0, "ethertype 0x%04x (only IPv4/IPv6)", etherType)
	}
}

func decodeNull(frame []byte) ([]byte, *ParseError) {
	// BSD loopback: 4-byte host-order address family (we accept both orders).
	if len(frame) < 4 {
		return nil, errf(KindDecodeTruncated, 0, "loopback header truncated")
	}
	af := binary.LittleEndian.Uint32(frame[0:4])
	switch af {
	case 2, 24, 28, 30: // AF_INET (LE/BE), AF_INET6
	default:
		af = binary.BigEndian.Uint32(frame[0:4])
	}
	switch af {
	case 2: // IPv4
		return frame[4:], nil
	case 24, 28, 30: // IPv6 (platform-dependent constants)
		return frame[4:], nil
	default:
		return nil, errf(KindUnsupportedEtherType, 0, "loopback address family %d", af)
	}
}

func decodeSLL(frame []byte) ([]byte, *ParseError) {
	// Linux cooked capture v1: 16-byte header, protocol at offset 14.
	if len(frame) < 16 {
		return nil, errf(KindDecodeTruncated, 0, "SLL header truncated")
	}
	etherType := binary.BigEndian.Uint16(frame[14:16])
	switch etherType {
	case 0x0800, 0x86dd:
		return frame[16:], nil
	default:
		return nil, errf(KindUnsupportedEtherType, 0, "SLL ethertype 0x%04x", etherType)
	}
}

func decodeSLL2(frame []byte) ([]byte, *ParseError) {
	// Linux cooked capture v2: 20-byte header, protocol type at offset 0.
	if len(frame) < 20 {
		return nil, errf(KindDecodeTruncated, 0, "SLL2 header truncated")
	}
	etherType := binary.BigEndian.Uint16(frame[0:2])
	switch etherType {
	case 0x0800, 0x86dd:
		return frame[20:], nil
	default:
		return nil, errf(KindUnsupportedEtherType, 0, "SLL2 ethertype 0x%04x", etherType)
	}
}

func decodeIPv4(pkt *Packet, data []byte) *ParseError {
	if len(data) < 20 {
		return errf(KindDecodeTruncated, pkt.Index, "IPv4 header truncated (%d bytes)", len(data))
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || ihl > len(data) {
		return errf(KindDecodeTruncated, pkt.Index, "IPv4 IHL=%d invalid", data[0]&0x0f)
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen != 0 && totalLen < ihl {
		return errf(KindDecodeTruncated, pkt.Index, "IPv4 total length %d < IHL %d", totalLen, ihl)
	}
	end := len(data)
	if totalLen != 0 && totalLen < end {
		end = totalLen
	}
	frag := binary.BigEndian.Uint16(data[6:8])
	moreFrags := frag&0x2000 != 0
	fragOff := frag & 0x1fff
	if moreFrags || fragOff != 0 {
		return errf(KindIPFragment, pkt.Index, "IPv4 fragment (offset=%d MF=%v)", fragOff*8, moreFrags)
	}
	pkt.Version = 4
	pkt.Proto = data[9]
	pkt.SrcIPLen, pkt.DstIPLen = 4, 4
	copy(pkt.SrcIP[:4], data[12:16])
	copy(pkt.DstIP[:4], data[16:20])
	return decodeTransport(pkt, data[ihl:end])
}

var v6ExtHdrs = map[uint8]bool{0: true, 43: true, 44: true, 50: true, 51: true, 60: true}

func decodeIPv6(pkt *Packet, data []byte) *ParseError {
	if len(data) < 40 {
		return errf(KindDecodeTruncated, pkt.Index, "IPv6 header truncated (%d bytes)", len(data))
	}
	payloadLen := int(binary.BigEndian.Uint16(data[4:6]))
	next := data[6]
	pkt.Version = 6
	pkt.Proto = next
	pkt.SrcIPLen, pkt.DstIPLen = 16, 16
	copy(pkt.SrcIP[:16], data[8:24])
	copy(pkt.DstIP[:16], data[24:40])
	rest := data[40:]
	if payloadLen < len(rest) {
		rest = rest[:payloadLen]
	}
	// Walk extension headers; fragment header rejects non-first fragments.
	for v6ExtHdrs[next] {
		if len(rest) < 8 {
			return errf(KindDecodeTruncated, pkt.Index, "IPv6 extension header truncated")
		}
		if next == 44 { // fragment header, fixed 8 bytes
			off := binary.BigEndian.Uint16(rest[2:4])
			if off&0xfff8 != 0 || off&0x0001 != 0 {
				return errf(KindIPFragment, pkt.Index, "IPv6 non-first fragment")
			}
			next = rest[0]
			rest = rest[8:]
			continue
		}
		hdrLen := int(rest[1])*8 + 8
		if hdrLen > len(rest) {
			return errf(KindDecodeTruncated, pkt.Index, "IPv6 extension header length invalid")
		}
		next = rest[0]
		rest = rest[hdrLen:]
	}
	pkt.Proto = next
	return decodeTransport(pkt, rest)
}

func decodeTransport(pkt *Packet, seg []byte) *ParseError {
	switch pkt.Proto {
	case 6: // TCP
		if len(seg) < 20 {
			return errf(KindDecodeTruncated, pkt.Index, "TCP header truncated (%d bytes)", len(seg))
		}
		dataOff := int(seg[12]>>4) * 4
		if dataOff < 20 || dataOff > len(seg) {
			return errf(KindDecodeTruncated, pkt.Index, "TCP data offset %d invalid", seg[12]>>4)
		}
		pkt.TCP = &TCPHeader{
			SrcPort: binary.BigEndian.Uint16(seg[0:2]),
			DstPort: binary.BigEndian.Uint16(seg[2:4]),
			Seq:     binary.BigEndian.Uint32(seg[4:8]),
			Ack:     binary.BigEndian.Uint32(seg[8:12]),
			DataOff: uint8(dataOff),
			Flags:   seg[13],
			Window:  binary.BigEndian.Uint16(seg[14:16]),
		}
		pkt.Payload = seg[dataOff:]
		return nil
	case 17: // UDP
		if len(seg) < 8 {
			return errf(KindDecodeTruncated, pkt.Index, "UDP header truncated (%d bytes)", len(seg))
		}
		pkt.UDP = &UDPHeader{
			SrcPort: binary.BigEndian.Uint16(seg[0:2]),
			DstPort: binary.BigEndian.Uint16(seg[2:4]),
		}
		pkt.Payload = seg[8:]
		return nil
	default:
		return errf(KindUnsupportedProtocol, pkt.Index, "IP protocol %d (only TCP/UDP)", pkt.Proto)
	}
}
