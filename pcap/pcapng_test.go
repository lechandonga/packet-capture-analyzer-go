package pcap_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/lechandonga/packet-capture-analyzer-go/internal/pcapgen"
	"github.com/lechandonga/packet-capture-analyzer-go/internal/testutil"
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
)

func TestPCAPNGBasic(t *testing.T) {
	testutil.DomainBanner(t, "pcapng")
	c := testutil.Start(t, "pcapng", "basic-epb-decode")
	b := pcapgen.NewNG()
	b.Add(pcapgen.EthIP4TCP(macS, macD, ipS, ipD, 1234, 80, 1, 0, pcap.TCPSyn, nil))
	b.Add(pcapgen.EthIP4TCP(macD, macS, ipD, ipS, 80, 1234, 1, 1, pcap.TCPSyn|pcap.TCPAck, nil))
	r, err := pcap.NewReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		c.Fail("header: %v", err)
		return
	}
	if r.Format() != pcap.FormatPCAPNG {
		c.Fail("format=%s", r.Format())
		return
	}
	n := 0
	for {
		_, e := r.Read()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			c.Fail("read: %v", e)
			return
		}
		n++
	}
	if n != 2 {
		c.Fail("decoded=%d want 2", n)
		return
	}
	c.Pass("decoded %d EPBs from pcapng", n)
}

func TestPCAPNGTruncation(t *testing.T) {
	testutil.DomainBanner(t, "pcapng")
	t.Run("truncated EPB body", func(t *testing.T) {
		c := testutil.Start(t, "pcapng", "truncated-epb")
		full := pcapgen.NewNG().Add(pcapgen.EthIP4TCP(macS, macD, ipS, ipD, 1, 80, 1, 0, pcap.TCPSyn, nil)).Bytes()
		_, err := pcap.NewReader(bytes.NewReader(full[:len(full)-8]))
		// header is fine; error happens on first Read
		if err != nil {
			c.Fail("unexpected header err %v", err)
			return
		}
		r, _ := pcap.NewReader(bytes.NewReader(full[:len(full)-8]))
		_, e := r.Read()
		if pe, ok := e.(*pcap.ParseError); !ok {
			c.Fail("want ParseError, got %v", e)
			return
		} else {
			c.Pass("classified %s", pe.Kind)
		}
	})
}
