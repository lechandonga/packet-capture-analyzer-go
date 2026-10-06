package proto_test

import "bytes"

func bytesNewReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func ipv6UDP() []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	ip[6] = 17
	src := []byte{0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dst := []byte{0x20, 0x01, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	copy(ip[8:24], src)
	copy(ip[24:40], dst)
	udp := []byte{0x04, 0xd2, 0x00, 0x35, 0x00, 0x0d, 0x00, 0x00, 'q', 'u', 'e', 'r', 'y'}
	ip[4], ip[5] = 0, byte(len(udp))
	return append(ip, udp...)
}
