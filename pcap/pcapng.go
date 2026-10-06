package pcap

import (
	"encoding/binary"
	"errors"
	"io"
)

// Minimal pcapng reader: Section Header Block, Interface Description Block,
// Enhanced Packet Block and Simple Packet Block are decoded; other blocks are
// skipped by length. Byte order is tracked per Reader so several files can be
// parsed concurrently.

// readNGHeader consumes the rest of the Section Header Block (the 4-byte
// section magic was already read by NewReader).
func (r *Reader) readNGHeader() error {
	r.order = binary.BigEndian
	// After the 4-byte magic: blockTotalLength(4) byteOrderMagic(4)
	// major(2) minor(2) sectionLength(8) = 20 fixed bytes, followed by
	// optional options and the 4-byte trailing block length.
	rest := make([]byte, 20)
	if _, err := io.ReadFull(r.br, rest); err != nil {
		return errf(KindTruncatedHeader, -1, "pcapng SHB: %v", err)
	}
	bom := rest[4:8]
	switch {
	case bom[0] == 0x1a && bom[1] == 0x2b && bom[2] == 0x3c && bom[3] == 0x4d:
		r.order = binary.BigEndian
	case bom[3] == 0x1a && bom[2] == 0x2b && bom[1] == 0x3c && bom[0] == 0x4d:
		r.order = binary.LittleEndian
	default:
		return errf(KindBadMagic, -1, "pcapng byte-order magic invalid: % x", bom)
	}
	blockLen := r.order.Uint32(rest[0:4])
	major := r.order.Uint16(rest[8:10])
	minor := r.order.Uint16(rest[10:12])
	if major != 1 || minor > 2 {
		return errf(KindUnsupportedVersion, -1, "pcapng version %d.%d not supported", major, minor)
	}
	if blockLen < 28 || blockLen%4 != 0 {
		return errf(KindCorrupt, -1, "pcapng SHB block length %d invalid", blockLen)
	}
	// bytes still unread in this block: blockLen - 4(magic) - 20(fixed);
	// this covers options plus the 4-byte trailing length.
	remaining := int(blockLen) - 24 // options plus 4-byte trailing length
	discard := make([]byte, remaining)
	if _, err := io.ReadFull(r.br, discard); err != nil {
		return errf(KindTruncatedHeader, -1, "pcapng SHB options/trailer: %v", err)
	}

	return nil
}

func (r *Reader) readNGRecord() ([]byte, TS, LinkType, uint32, uint32, error) {
	for {
		h := make([]byte, 8)
		_, err := io.ReadFull(r.br, h)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil, TS{}, 0, 0, 0, io.EOF
			}
			return nil, TS{}, 0, 0, 0, errf(KindTruncatedHeader, r.stats.Packets, "pcapng block header: %v", err)
		}
		bt := r.order.Uint32(h[0:4])
		bl := r.order.Uint32(h[4:8])
		if bl < 12 || bl%4 != 0 {
			return nil, TS{}, 0, 0, 0, errf(KindCorrupt, r.stats.Packets, "pcapng block length %d (type %x) invalid", bl, bt)
		}
		// Read everything after the 8-byte header, including the 4-byte
		// trailing block length; parse only the prefix before that trailer.
		full := make([]byte, int(bl)-8)
		if _, err := io.ReadFull(r.br, full); err != nil {
			return nil, TS{}, 0, 0, 0, errf(KindTruncatedPacket, r.stats.Packets, "pcapng block body: %v", err)
		}

		body := full[:len(full)-4]
		switch bt {
		case 0x0A0D0D0A: // concatenated SHB: interfaces are reset
			r.ifaces = nil
			continue
		case 0x00000001: // IDB
			ifc, ok := parseIDB(r.order, body)
			if !ok {
				return nil, TS{}, 0, 0, 0, errf(KindCorrupt, r.stats.Packets, "interface description block too short")
			}
			r.ifaces = append(r.ifaces, ifc)
			if len(r.ifaces) == 1 && r.link == 0 {
				r.link = ifc.link
				r.stats.Link = ifc.link
			}
			continue
		case 0x00000006: // EPB
			return r.readEPB(body)
		case 0x00000003: // SPB
			return r.readSPB(body)
		default:
			continue // unknown block: skipped by length

		}
	}
}

func parseIDB(order binary.ByteOrder, body []byte) (ngIface, bool) {
	if len(body) < 8 {
		return ngIface{}, false
	}
	ifc := ngIface{
		link:    LinkType(order.Uint16(body[0:2])),
		snap:    order.Uint32(body[4:8]),
		tsResol: 6,
	}
	// Options only exist when the block body is longer than the fixed 8
	// bytes (and the caller already stripped the trailing block length).
	var opts []byte
	if len(body) > 8 {
		opts = body[8:]
	}
	for len(opts) >= 4 {
		code := order.Uint16(opts[0:2])
		ln := int(order.Uint16(opts[2:4]))
		opts = opts[4:]
		if code == 0 {
			break
		}
		if ln > len(opts) {
			break
		}
		val := opts[:ln]
		switch code {
		case 9: // if_tsresol
			if len(val) >= 1 {
				ifc.tsResol = val[0]
			}
		case 14: // if_tsoffset
			if ln == 8 {
				ifc.tsOff = int64(order.Uint64(val))
			}
		}
		opts = opts[(ln+3)&^3:]
	}
	return ifc, true
}

func (r *Reader) readEPB(body []byte) ([]byte, TS, LinkType, uint32, uint32, error) {
	if len(body) < 20 {
		return nil, TS{}, 0, 0, 0, errf(KindCorrupt, r.stats.Packets, "EPB too short")
	}
	id := r.order.Uint32(body[0:4])
	if int(id) >= len(r.ifaces) {
		return nil, TS{}, 0, 0, 0, errf(KindCorrupt, r.stats.Packets, "EPB references interface %d but only %d defined", id, len(r.ifaces))
	}
	ifc := r.ifaces[id]
	hi := r.order.Uint32(body[4:8])
	lo := r.order.Uint32(body[8:12])
	capLen := r.order.Uint32(body[12:16])
	rawLen := r.order.Uint32(body[16:20])
	if int(capLen) > len(body)-20 {
		return nil, TS{}, 0, 0, 0, errf(KindTruncatedPacket, r.stats.Packets, "EPB incl_len=%d exceeds block", capLen)
	}
	rec := make([]byte, capLen)
	copy(rec, body[20:20+capLen])
	ts := ngTimestamp(uint64(hi)<<32|uint64(lo), ifc)
	return rec, ts, ifc.link, capLen, rawLen, nil
}

func (r *Reader) readSPB(body []byte) ([]byte, TS, LinkType, uint32, uint32, error) {
	if len(r.ifaces) == 0 {
		return nil, TS{}, 0, 0, 0, errf(KindCorrupt, r.stats.Packets, "SPB without an interface definition")
	}
	if len(body) < 4 {
		return nil, TS{}, 0, 0, 0, errf(KindCorrupt, r.stats.Packets, "SPB too short")
	}
	ifc := r.ifaces[0]
	rawLen := r.order.Uint32(body[0:4])
	n := len(body) - 4
	if ifc.snap != 0 && uint32(n) > ifc.snap {
		n = int(ifc.snap)
	}
	if rawLen != 0 && int(rawLen) < n {
		n = int(rawLen)
	}
	rec := make([]byte, n)
	copy(rec, body[4:4+n])
	return rec, TS{}, ifc.link, uint32(n), rawLen, nil
}

func ngTimestamp(ts uint64, ifc ngIface) TS {
	base := ifc.tsResol & 0x7f
	var sec, frac int64
	switch {
	case ifc.tsResol&0x80 != 0:
		if base >= 64 {
			sec, frac = 0, 0
		} else {
			unit := uint64(1) << base
			sec = int64(ts / unit)
			frac = int64((ts%unit)*1_000_000) / int64(unit)
		}
	default:
		mult := uint64(1)
		for i := byte(0); i < base; i++ {
			mult *= 10
			if mult == 0 {
				break
			}
		}
		if mult == 0 {
			mult = 1
		}
		sec = int64(ts / mult)
		frac = int64((ts%mult)*1_000_000) / int64(mult)
	}
	return TS{Sec: sec + ifc.tsOff, Usec: frac}
}
