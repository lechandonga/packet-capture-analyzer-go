package pcap_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/lechandonga/packet-capture-analyzer-go/internal/pcapgen"
	"github.com/lechandonga/packet-capture-analyzer-go/internal/testutil"
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
)

var (
	macS = [6]byte{0, 0, 0, 0, 0, 1}
	macD = [6]byte{0, 0, 0, 0, 0, 2}
	ipS  = [4]byte{10, 0, 0, 1}
	ipD  = [4]byte{10, 0, 0, 2}
)

func parseAll(t *testing.T, data []byte) ([]*pcap.Packet, *pcap.Reader, error) {
	t.Helper()
	r, err := pcap.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	var pkts []*pcap.Packet
	for {
		p, perr := r.Read()
		if errors.Is(perr, io.EOF) {
			break
		}
		if perr != nil {
			return pkts, r, perr
		}
		pkts = append(pkts, p)
	}
	return pkts, r, nil
}

func TestMalformedAndTruncatedCaptures(t *testing.T) {
	testutil.DomainBanner(t, "pcap-parsing")

	t.Run("empty file gives truncated_header", func(t *testing.T) {
		c := testutil.Start(t, "pcap-parsing", "empty-file")
		_, err := pcap.NewReader(bytes.NewReader(nil))
		if pe, ok := err.(*pcap.ParseError); !ok || pe.Kind != pcap.KindTruncatedHeader {
			c.Fail("want truncated_header, got %v", err)
			return
		}
		c.Pass("empty file reported as %v", err)
	})

	t.Run("bad magic is classified not panicked", func(t *testing.T) {
		c := testutil.Start(t, "pcap-parsing", "bad-magic")
		_, err := pcap.NewReader(bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8}))
		if pe, ok := err.(*pcap.ParseError); !ok || pe.Kind != pcap.KindBadMagic {
			c.Fail("want bad_magic, got %v", err)
			return
		}
		c.Pass("magic error kind=%v", err.(*pcap.ParseError).Kind)
	})

	t.Run("unsupported version", func(t *testing.T) {
		c := testutil.Start(t, "pcap-parsing", "unsupported-version")
		b := pcapgen.New()
		data := b.WithHeader(func(hdr []byte) {
			hdr[4] = 3 // major version 3
			hdr[5] = 0
		})
		_, err := pcap.NewReader(bytes.NewReader(data))
		if pe, ok := err.(*pcap.ParseError); !ok || pe.Kind != pcap.KindUnsupportedVersion {
			c.Fail("want unsupported_version, got %v", err)
			return
		}
		c.Pass("version rejected: %v", err)
	})

	t.Run("unsupported link type", func(t *testing.T) {
		c := testutil.Start(t, "pcap-parsing", "unsupported-linktype")
		b := pcapgen.NewLink(9999)
		b.Add(pcapgen.Ethernet(macS, macD, 0x0800,
			pcapgen.IPv4(ipS, ipD, 6, pcapgen.TCP(1, 2, 100, 0, pcap.TCPSyn, nil))))
		_, err := pcap.NewReader(bytes.NewReader(b.Bytes()))
		if pe, ok := err.(*pcap.ParseError); !ok || pe.Kind != pcap.KindUnsupportedLinkType {
			c.Fail("want unsupported_link_type, got %v", err)
			return
		}
		c.Pass("link type rejected: %v", err)
	})

	t.Run("truncated global header", func(t *testing.T) {
		c := testutil.Start(t, "pcap-parsing", "truncated-global-header")
		full := pcapgen.New().Bytes()
		_, err := pcap.NewReader(bytes.NewReader(full[:10]))
		if pe, ok := err.(*pcap.ParseError); !ok || pe.Kind != pcap.KindTruncatedHeader {
			c.Fail("got %v", err)
			return
		}
		c.Pass("short header rejected")
	})

	t.Run("truncated packet body reports truncated_packet", func(t *testing.T) {
		c := testutil.Start(t, "pcap-parsing", "truncated-packet-body")
		b := pcapgen.New()
		b.Add(pcapgen.EthIP4TCP(macS, macD, ipS, ipD, 1234, 80, 1, 0, pcap.TCPSyn, nil))
		full := b.Bytes()
		// cut the last 10 bytes of the frame (record header says full size)
		pkts, _, err := parseAll(t, full[:len(full)-10])
		if pe, ok := err.(*pcap.ParseError); !ok || pe.Kind != pcap.KindTruncatedPacket {
			c.Fail("want truncated_packet, got %v (pkts=%d)", err, len(pkts))
			return
		}
		c.Pass("kind=%s index=%d", err.(*pcap.ParseError).Kind, err.(*pcap.ParseError).Index)
	})

	t.Run("snaplen-truncated frame is a classified skip, not fatal", func(t *testing.T) {
		c := testutil.Start(t, "pcap-parsing", "snaplen-truncated-frame")
		b := pcapgen.New()
		frame := pcapgen.EthIP4TCP(macS, macD, ipS, ipD, 1234, 80, 1, 0, pcap.TCPSyn, nil)
		b.Add(frame[:20]) // shorter than Ethernet header
		pkts, r, err := parseAll(t, b.Bytes())
		if err != nil {
			c.Fail("unexpected fatal error %v", err)
			return
		}
		if len(pkts) != 0 || r.Stats().SkipReasons[pcap.KindDecodeTruncated] != 1 {
			c.Fail("want 1 decode-truncated skip, got pkts=%d stats=%+v", len(pkts), r.Stats())
			return
		}
		c.Pass("skipped as packet_decode_truncated; reader continues")
	})
}

func TestLinkTypesAndVLAN(t *testing.T) {
	testutil.DomainBanner(t, "link-types")

	ip := pcapgen.IPv4(ipS, ipD, 6, pcapgen.TCP(1, 2, 1, 0, pcap.TCPSyn, nil))

	cases := []struct {
		name string
		link uint16
		frm  []byte
	}{
		{"ethernet", 1, pcapgen.Ethernet(macS, macD, 0x0800, ip)},
		{"null-loopback", 0, pcapgen.Null(ip)},
		{"raw-ip", 101, ip},
		{"linux-sll", 113, pcapgen.SLL(ip)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testutil.Start(t, "link-types", tc.name)
			b := pcapgen.NewLink(tc.link)
			b.Add(tc.frm)
			pkts, _, err := parseAll(t, b.Bytes())
			if err != nil {
				c.Fail("parse: %v", err)
				return
			}
			if len(pkts) != 1 || pkts[0].TCP == nil {
				c.Fail("want 1 decoded TCP packet, got %d", len(pkts))
				return
			}
			c.Pass("decoded %s syn=%d", tc.name, pkts[0].TCP.Flags)
		})
	}

	t.Run("vlan-tagged ethernet", func(t *testing.T) {
		c := testutil.Start(t, "link-types", "vlan")
		frm := pcapgen.Ethernet(macS, macD, 0x8100, append([]byte{0x00, 0x10, 0x08, 0x00}, ip...))
		b := pcapgen.New().Add(frm)
		pkts, _, err := parseAll(t, b.Bytes())
		if err != nil || len(pkts) != 1 || pkts[0].TCP == nil {
			c.Fail("vlan decode failed: %v pkts=%d", err, len(pkts))
			return
		}
		c.Pass("VLAN tag stripped, TCP decoded")
	})
}

func TestDeterministicReadsAcrossChunkSizes(t *testing.T) {
	testutil.DomainBanner(t, "pcap-parsing")
	c := testutil.Start(t, "pcap-parsing", "chunk-size-invariance")

	b := pcapgen.New()
	for i := uint32(0); i < 30; i++ {
		payload := []byte(strings.Repeat("x", int(1+i%5)))
		b.Add(pcapgen.EthIP4TCP(macS, macD, ipS, ipD, uint16(1000+i%50), 80, 1000+i, 0, pcap.TCPPsh|pcap.TCPAck, payload))
	}
	data := b.Bytes()

	reference, _, err := parseAll(t, data)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range []int{1, 7, 31, 128, 4096} {
		r, err := pcap.NewReader(&chunkReader{data: data, n: chunk})
		if err != nil {
			t.Fatal(err)
		}
		var got []*pcap.Packet
		for {
			p, e := r.Read()
			if errors.Is(e, io.EOF) {
				break
			}
			if e != nil {
				t.Fatalf("chunk=%d: %v", chunk, e)
			}
			got = append(got, p)
		}
		if len(got) != len(reference) {
			c.Fail("chunk=%d got %d packets want %d", chunk, len(got), len(reference))
			return
		}
		for i := range got {
			if got[i].TCP.Seq != reference[i].TCP.Seq || string(got[i].Payload) != string(reference[i].Payload) {
				c.Fail("chunk=%d packet %d mismatch", chunk, i)
				return
			}
		}
	}
	c.Pass("all 5 chunk schedules decode identically (%d packets)", len(reference))
}

type chunkReader struct {
	data []byte
	n    int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := c.n
	if n > len(p) {
		n = len(p)
	}
	if n > len(c.data) {
		n = len(c.data)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}
