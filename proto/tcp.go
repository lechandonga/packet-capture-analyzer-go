package proto

import "fmt"

func decodeTCP(b []byte) (*TCPHeader, []byte, error) {
	if len(b) < 20 {
		return nil, nil, fmt.Errorf("%w: tcp header", ErrShortFrame)
	}
	doff := int(b[12]>>4) * 4
	if doff < 20 {
		return nil, nil, fmt.Errorf("%w: tcp data offset %d bytes", ErrMalformed, doff)
	}
	if len(b) < doff {
		return nil, nil, fmt.Errorf("%w: tcp options", ErrShortFrame)
	}
	t := &TCPHeader{
		SrcPort: uint16(b[0])<<8 | uint16(b[1]),
		DstPort: uint16(b[2])<<8 | uint16(b[3]),
		Seq:     uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7]),
		Ack:     uint32(b[8])<<24 | uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11]),
		Flags:   TCPFlags(b[13]),
		Window:  uint16(b[14])<<8 | uint16(b[15]),
	}
	return t, append([]byte(nil), b[doff:]...), nil
}
