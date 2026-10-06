package session

import (
	"bytes"

	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
)

// canonicalKey returns the FlowKey and reports whether the packet travels
// A->B, where A/B are the numerically smaller/larger endpoints. Session-level
// initiator direction is tracked separately via Session.initIsA.
func canonicalKey(p *pcap.Packet) (FlowKey, bool) {
	var proto uint8
	var sport, dport uint16
	var src, dst []byte
	if p.TCP != nil {
		proto, sport, dport = 6, p.TCP.SrcPort, p.TCP.DstPort
		src, dst = p.Src(), p.Dst()
	} else {
		proto, sport, dport = 17, p.UDP.SrcPort, p.UDP.DstPort
		src, dst = p.Src(), p.Dst()
	}
	var a, b [16]byte
	if endpointLess(src, sport, dst, dport) {
		copy(a[:], src)
		copy(b[:], dst)
		return FlowKey{Proto: proto, AIP: a, APort: sport, AIPLen: len(src), BIP: b, BPort: dport, BIPLen: len(dst)}, true
	}
	copy(a[:], dst)
	copy(b[:], src)
	return FlowKey{Proto: proto, AIP: a, APort: dport, AIPLen: len(dst), BIP: b, BPort: sport, BIPLen: len(src)}, false
}

func endpointLess(ipA []byte, portA uint16, ipB []byte, portB uint16) bool {
	if c := bytes.Compare(ipA, ipB); c != 0 {
		return c < 0
	}
	return portA < portB
}
