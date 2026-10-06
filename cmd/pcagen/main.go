// Command pcagen writes a deterministic synthetic pcap to a path, purely for
// offline demos and smoke tests. It never touches the network.
package main

import (
	"flag"
	"os"

	"github.com/lechandonga/packet-capture-analyzer-go/internal/pcapgen"
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
)

func main() {
	out := flag.String("out", "scan.pcap", "output path")
	kind := flag.String("kind", "portscan", "capture kind: portscan|periodic|normal")
	flag.Parse()

	var src = [4]byte{10, 0, 0, 9}
	var dst = [4]byte{10, 1, 1, 1}
	var m1 = [6]byte{1}
	var m2 = [6]byte{2}
	b := pcapgen.New()
	switch *kind {
	case "portscan":
		for port := uint16(1); port <= 25; port++ {
			u := uint32(port) * 10000
			b.AddAt(u, pcapgen.EthIP4TCP(m1, m2, src, dst, uint16(30000+int(port)), port, 1, 0, pcap.TCPSyn, nil))
			b.AddAt(u+100, pcapgen.EthIP4TCP(m2, m1, dst, src, port, uint16(30000+int(port)), 1, 1, pcap.TCPRst|pcap.TCPAck, nil))
		}
	case "periodic":
		var src2 = [4]byte{10, 5, 5, 5}
		var dst2 = [4]byte{198, 51, 100, 10}
		for i := 0; i < 7; i++ {
			u := uint32(i) * 60_000_000
			b.AddAt(u, pcapgen.EthIP4TCP(m1, m2, src2, dst2, uint16(50000+i), 443, 700+uint32(i), 0, pcap.TCPSyn, nil))
			b.AddAt(u+100, pcapgen.EthIP4TCP(m2, m1, dst2, src2, 443, uint16(50000+i), 1, 701+uint32(i), pcap.TCPRst, nil))
		}
	default:
		b.Add(pcapgen.EthIP4TCP(m1, m2, src, dst, 40000, 443, 1000, 0, pcap.TCPSyn, nil))
		b.Add(pcapgen.EthIP4TCP(m2, m1, dst, src, 443, 40000, 5000, 1001, pcap.TCPSyn|pcap.TCPAck, nil))
		b.Add(pcapgen.EthIP4TCP(m1, m2, src, dst, 40000, 443, 1001, 5001, pcap.TCPAck, []byte("hello")))
	}
	if err := os.WriteFile(*out, b.Bytes(), 0o644); err != nil {
		panic(err)
	}
}
