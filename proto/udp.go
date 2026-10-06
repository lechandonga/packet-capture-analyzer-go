package proto

import "fmt"

func decodeUDP(b []byte) (*UDPHeader, []byte, error) {
	if len(b) < 8 {
		return nil, nil, fmt.Errorf("%w: udp header", ErrShortFrame)
	}
	u := &UDPHeader{
		SrcPort: uint16(b[0])<<8 | uint16(b[1]),
		DstPort: uint16(b[2])<<8 | uint16(b[3]),
		Length:  uint16(b[4])<<8 | uint16(b[5]),
	}
	if u.Length != 0 && int(u.Length) < 8 {
		return nil, nil, fmt.Errorf("%w: udp length %d", ErrMalformed, u.Length)
	}
	payload := b[8:]
	if u.Length >= 8 && int(u.Length)-8 < len(payload) {
		payload = payload[:int(u.Length)-8]
	}
	return u, append([]byte(nil), payload...), nil
}
