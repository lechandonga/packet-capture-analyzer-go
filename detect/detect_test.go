package detect_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/lechandonga/packet-capture-analyzer-go/detect"
	"github.com/lechandonga/packet-capture-analyzer-go/internal/pcapgen"
	"github.com/lechandonga/packet-capture-analyzer-go/internal/testutil"
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
	"github.com/lechandonga/packet-capture-analyzer-go/rules"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

func runCapture(t *testing.T, b *pcapgen.Builder) []*session.Session {
	t.Helper()
	r, err := pcap.NewReader(bytes.NewReader(b.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	eng := session.NewEngine(session.Config{})
	for {
		p, e := r.Read()
		if e != nil {
			break
		}
		eng.HandlePacket(p)
	}
	return eng.Flush()
}

func TestPortScanDetection(t *testing.T) {
	testutil.DomainBanner(t, "detection")
	c := testutil.Start(t, "detection", "port-scan")

	var src = [4]byte{10, 0, 0, 9}
	var dst = [4]byte{10, 1, 1, 1}
	b := pcapgen.New()
	for port := uint16(1); port <= 25; port++ {
		b.AddAt(uint32(port)*10000, pcapgen.EthIP4TCP(
			[6]byte{0, 0, 0, 0, 0, 1}, [6]byte{0, 0, 0, 0, 0, 2},
			src, dst, 30000, port, 1, 0, pcap.TCPSyn, nil))
		// RST back => failed attempt
		b.AddAt(uint32(port)*10000+50, pcapgen.EthIP4TCP(
			[6]byte{0, 0, 0, 0, 0, 2}, [6]byte{0, 0, 0, 0, 0, 1},
			dst, src, port, 30000, 1, 1, pcap.TCPRst|pcap.TCPAck, nil))
	}
	sessions := runCapture(t, b)
	st, _ := rules.NewStore(rules.DefaultRules())
	det := detect.New(st.Current())
	for _, s := range sessions {
		det.Observe(s)
	}
	found := det.Finalize()

	var scan *detect.Finding
	for i := range found {
		if found[i].RuleType == rules.RulePortScan {
			scan = &found[i]
		}
	}
	if scan == nil {
		c.Fail("no port_scan finding; findings=%d", len(found))
		return
	}
	if len(scan.Evidence) < 20 {
		c.Fail("evidence=%d < 20", len(scan.Evidence))
		return
	}
	if scan.RuleVersion != 1 {
		c.Fail("rule version %d", scan.RuleVersion)
		return
	}
	c.Pass("port_scan value=%d evidence=%d (traceable to sessions)", scan.Value, len(scan.Evidence))
}

func TestRepeatedFailuresDetection(t *testing.T) {
	testutil.DomainBanner(t, "detection")
	c := testutil.Start(t, "detection", "repeated-failed-connections")

	var src = [4]byte{10, 0, 0, 20}
	var dst = [4]byte{10, 2, 2, 2}
	b := pcapgen.New()
	for i := 0; i < 12; i++ {
		u := uint32(i) * 100_000
		b.AddAt(u, pcapgen.EthIP4TCP([6]byte{1}, [6]byte{2}, src, dst, uint16(41000+i), 22, 100, 0, pcap.TCPSyn, nil))
		b.AddAt(u+100, pcapgen.EthIP4TCP([6]byte{2}, [6]byte{1}, dst, src, 22, uint16(41000+i), 1, 101, pcap.TCPRst|pcap.TCPAck, nil))
	}
	sessions := runCapture(t, b)
	st, _ := rules.NewStore(rules.DefaultRules())
	det := detect.New(st.Current())
	for _, s := range sessions {
		det.Observe(s)
	}
	var f *detect.Finding
	for _, x := range det.Finalize() {
		if x.RuleType == rules.RuleFailedConnect {
			f = &x
		}
	}
	if f == nil || f.Value < 10 {
		c.Fail("want repeated-failure finding >=10, got %+v", f)
		return
	}
	c.Pass("failed-conn value=%d window=%dus", f.Value, f.WindowUsec)
}

func TestPeriodicBeaconDetection(t *testing.T) {
	testutil.DomainBanner(t, "detection")
	c := testutil.Start(t, "detection", "periodic-outbound")

	var src = [4]byte{10, 5, 5, 5}
	var dst = [4]byte{198, 51, 100, 10}
	b := pcapgen.New()
	const periodUsec uint32 = 60_000_000
	for i := 0; i < 7; i++ {
		u := uint32(i) * periodUsec
		b.AddAt(u, pcapgen.EthIP4TCP([6]byte{1}, [6]byte{2}, src, dst, 50000+uint16(i), 443, 700+uint32(i), 0, pcap.TCPSyn, nil))
		b.AddAt(u+100, pcapgen.EthIP4TCP([6]byte{2}, [6]byte{1}, dst, src, 443, 50000+uint16(i), 1, 701+uint32(i), pcap.TCPRst, nil))
	}
	sessions := runCapture(t, b)
	st, _ := rules.NewStore(rules.DefaultRules())
	det := detect.New(st.Current())
	for _, s := range sessions {
		det.Observe(s)
	}
	var f *detect.Finding
	for _, x := range det.Finalize() {
		if x.RuleType == rules.RulePeriodicOutbound {
			f = &x
		}
	}
	if f == nil {
		c.Fail("no periodic finding")
		return
	}
	c.Pass("periodic finding: %s evidence=%d", f.Metric, len(f.Evidence))

	t.Run("replay produces identical findings", func(t *testing.T) {
		c2 := testutil.Start(t, "detection", "replay-determinism")
		sessions2 := runCapture(t, b)
		d2 := detect.New(st.Current())
		for _, s := range sessions2 {
			d2.Observe(s)
		}
		first := fmt.Sprintf("%+v", det.Finalize())
		second := fmt.Sprintf("%+v", d2.Finalize())
		if first != second {
			c2.Fail("replay differs")
			return
		}
		c2.Pass("identical conclusions across replays")
	})
}

func TestRuleVersionPinnedDuringAnalysis(t *testing.T) {
	testutil.DomainBanner(t, "detection")
	c := testutil.Start(t, "detection", "snapshot-pinning-under-update")

	var src = [4]byte{10, 9, 9, 9}
	var dst = [4]byte{10, 8, 8, 8}
	b := pcapgen.New()
	for port := uint16(1); port <= 12; port++ {
		u := uint32(port) * 10_000
		b.AddAt(u, pcapgen.EthIP4TCP([6]byte{1}, [6]byte{2}, src, dst, uint16(40000+port), port, 1, 0, pcap.TCPSyn, nil))
		b.AddAt(u+100, pcapgen.EthIP4TCP([6]byte{2}, [6]byte{1}, dst, src, port, uint16(40000+port), 1, 1, pcap.TCPRst, nil))
	}
	sessions := runCapture(t, b)

	// v1 threshold high -> no finding.
	r1 := []rules.Rule{{ID: "scan", Type: rules.RulePortScan, Enabled: true, WindowUsec: 10_000_000, Threshold: 50}}
	r2 := []rules.Rule{{ID: "scan", Type: rules.RulePortScan, Enabled: true, WindowUsec: 10_000_000, Threshold: 5}}
	st, _ := rules.NewStore(r1)
	det := detect.New(st.Current()) // pin v1
	if _, err := st.Update(r2); err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		det.Observe(s)
	}
	fs := det.Finalize()
	for _, f := range fs {
		if f.RuleVersion != 1 || f.RuleID == "scan" {
			c.Fail("detector used new rules while pinned: %+v", f)
			return
		}
	}
	// A fresh detector on v2 sees the scan.
	det2 := detect.New(st.Current())
	for _, s := range sessions {
		det2.Observe(s)
	}
	if len(det2.Finalize()) != 1 {
		c.Fail("v2 detector should fire once")
		return
	}
	c.Pass("pinned detector stayed on v1; new detector sees v2 findings")
}
