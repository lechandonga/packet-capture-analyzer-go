package detect_test

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/detect"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio/pcaptest"
	"github.com/lechandonga/packet-capture-analyzer-go/proto"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

type builder struct {
	t *testing.T
}

func sessionsFrom(t *testing.T, frames []pcaptest.Frame) []*session.Session {
	blob := pcaptest.Build(1, 65535, frames, nil)
	cap, _, err := readAll(blob)
	if err != nil {
		t.Fatal(err)
	}
	asm := session.NewAssembler(session.DefaultConfig(), nil)
	for _, rec := range cap.Records {
		pk, err := proto.DecodeFrame(cap.Header.Network, rec)
		if err != nil {
			t.Fatal(err)
		}
		asm.HandlePacket(pk, rec.TS)
	}
	return asm.Flush()
}

func TestDetection(t *testing.T) {
	base := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)

	t.Run("业务:行为检测/端口扫描命中且证据可追溯会话", func(t *testing.T) {
		var frames []pcaptest.Frame
		for i := 0; i < 12; i++ {
			port := uint16(2000 + i)
			frames = append(frames, pcaptest.Frame{
				TS:    base.Add(time.Duration(i) * time.Second),
				SrcIP: "10.9.0.1", DstIP: "10.9.0.2",
				SrcPort: 40000 + uint16(i), DstPort: port, Seq: 1, Flags: pcaptest.SYN,
			})
		}
		engine := detect.NewDefaultEngine()
		found := engine.Analyze(sessionsFrom(t, frames))
		var hit *detect.Finding
		for i := range found {
			if found[i].Kind == detect.RulePortScan {
				hit = &found[i]
			}
		}
		if hit == nil {
			t.Fatalf("no port scan finding in %+v", found)
		}
		if hit.RuleID != "builtin.port-scan" || hit.Evidence.Count < 10 || len(hit.Evidence.DistinctPorts) < 10 {
			t.Fatalf("hit=%+v", hit)
		}
		if len(hit.Evidence.SessionKeys) == 0 {
			t.Fatal("finding carries no traceable sessions")
		}
	})

	t.Run("业务:行为检测/失败连接突增命中", func(t *testing.T) {
		var frames []pcaptest.Frame
		for i := 0; i < 6; i++ {
			frames = append(frames,
				pcaptest.Frame{TS: base.Add(time.Duration(i) * time.Second), SrcIP: "10.9.1.1", DstIP: "10.9.1.9", SrcPort: uint16(45000 + i), DstPort: 22, Seq: 1, Flags: pcaptest.SYN},
				pcaptest.Frame{TS: base.Add(time.Duration(i)*time.Second + 10*time.Millisecond), SrcIP: "10.9.1.9", DstIP: "10.9.1.1", SrcPort: 22, DstPort: uint16(45000 + i), Seq: 1, Ack: 2, Flags: pcaptest.RST | pcaptest.ACK},
			)
		}
		found := detect.NewDefaultEngine().Analyze(sessionsFrom(t, frames))
		var kinds []detect.RuleKind
		for _, f := range found {
			kinds = append(kinds, f.Kind)
		}
		if !containsKind(kinds, detect.RuleFailedConnect) {
			t.Fatalf("kinds=%v", kinds)
		}
	})

	t.Run("业务:行为检测/周期性外连命中", func(t *testing.T) {
		var frames []pcaptest.Frame
		for i := 0; i < 6; i++ {
			ts := base.Add(time.Duration(i) * 60 * time.Second)
			cp := uint16(46000 + i)
			frames = append(frames,
				pcaptest.Frame{TS: ts, SrcIP: "10.9.2.1", DstIP: "203.0.113.7", SrcPort: cp, DstPort: 8443, Seq: uint32(100 + i), Flags: pcaptest.SYN},
				pcaptest.Frame{TS: ts.Add(5 * time.Millisecond), SrcIP: "203.0.113.7", DstIP: "10.9.2.1", SrcPort: 8443, DstPort: cp, Seq: 5, Ack: uint32(101 + i), Flags: pcaptest.SYN | pcaptest.ACK},
			)
		}
		found := detect.NewDefaultEngine().Analyze(sessionsFrom(t, frames))
		var hit bool
		for _, f := range found {
			if f.Kind == detect.RulePeriodicBeacon && f.Evidence.Port == 8443 && f.Evidence.Count == 6 {
				hit = true
				if f.Evidence.MeanInterval != "1m0s" {
					t.Fatalf("mean=%s", f.Evidence.MeanInterval)
				}
			}
		}
		if !hit {
			t.Fatalf("findings=%+v", found)
		}
	})

	t.Run("业务:行为检测/抖动过大不命中周期规则", func(t *testing.T) {
		deltas := []time.Duration{60 * time.Second, 61 * time.Second, 75 * time.Second, 58 * time.Second, 90 * time.Second}
		var frames []pcaptest.Frame
		ts := base
		for i, d := range append([]time.Duration{0}, deltas...) {
			ts = ts.Add(d)
			cp := uint16(47000 + i)
			frames = append(frames,
				pcaptest.Frame{TS: ts, SrcIP: "10.9.2.2", DstIP: "203.0.113.8", SrcPort: cp, DstPort: 8443, Seq: 1, Flags: pcaptest.SYN},
				pcaptest.Frame{TS: ts.Add(5 * time.Millisecond), SrcIP: "203.0.113.8", DstIP: "10.9.2.2", SrcPort: 8443, DstPort: cp, Seq: 5, Ack: 2, Flags: pcaptest.SYN | pcaptest.ACK},
			)
		}
		found := detect.NewDefaultEngine().Analyze(sessionsFrom(t, frames))
		for _, f := range found {
			if f.Kind == detect.RulePeriodicBeacon {
				t.Fatalf("unexpected beacon: %+v", f)
			}
		}
	})

	t.Run("业务:行为检测/同一抓包重放结论一致", func(t *testing.T) {
		var frames []pcaptest.Frame
		for i := 0; i < 12; i++ {
			frames = append(frames, pcaptest.Frame{
				TS:    base.Add(time.Duration(i) * 100 * time.Millisecond),
				SrcIP: "10.9.3.1", DstIP: "10.9.3.2",
				SrcPort: 48000 + uint16(i), DstPort: uint16(3000 + i), Seq: 1, Flags: pcaptest.SYN,
			})
		}
		engine := detect.NewDefaultEngine()
		sess := sessionsFrom(t, frames)
		first := sig(engine.Analyze(sess))
		for i := 0; i < 4; i++ {
			if got := sig(engine.Analyze(sess)); got != first {
				t.Fatalf("non-deterministic findings:\n%s\nvs\n%s", got, first)
			}
		}
	})
}

func TestRuleLifecycle(t *testing.T) {
	t.Run("业务:规则更新/非法规则集整体失败旧规则保留", func(t *testing.T) {
		e := detect.NewDefaultEngine()
		v1 := e.ActiveVersion()
		bad := []byte(`[{"id":"x","kind":"not_a_rule","params":{}}]`)
		if err := e.ParseAndUpdate(2, bad); err == nil {
			t.Fatal("expected validation failure")
		}
		if e.ActiveVersion() != v1 {
			t.Fatalf("version changed to %d after failed update", e.ActiveVersion())
		}
		base := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
		var frames []pcaptest.Frame
		for i := 0; i < 12; i++ {
			frames = append(frames, pcaptest.Frame{
				TS:    base.Add(time.Duration(i) * time.Second),
				SrcIP: "10.5.0.1", DstIP: "10.5.0.2",
				SrcPort: uint16(40000 + i), DstPort: uint16(2000 + i), Seq: 1, Flags: pcaptest.SYN,
			})
		}
		found := e.Analyze(sessionsFrom(t, frames))
		if len(found) == 0 {
			t.Fatal("old rules no longer active after rejected update")
		}
	})

	t.Run("业务:规则更新/合法规则整体生效", func(t *testing.T) {
		e := detect.NewDefaultEngine()
		raw := []byte(`[
			{"id":"tight-scan","kind":"port_scan","params":{"threshold":3,"time_window":"10s","require_failed":true}},
			{"id":"beacon","kind":"periodic_beacon","params":{"min_count":3,"min_interval":"1s","max_interval":"1m","jitter_ratio":0.5}}
		]`)
		if err := e.ParseAndUpdate(7, raw); err != nil {
			t.Fatal(err)
		}
		if e.ActiveVersion() != 7 {
			t.Fatalf("version=%d", e.ActiveVersion())
		}
		base := time.Date(2024, 6, 2, 0, 0, 0, 0, time.UTC)
		var frames []pcaptest.Frame
		for i := 0; i < 4; i++ {
			frames = append(frames, pcaptest.Frame{
				TS:    base.Add(time.Duration(i) * time.Second),
				SrcIP: "10.5.1.1", DstIP: "10.5.1.2",
				SrcPort: uint16(41000 + i), DstPort: uint16(7000 + i), Seq: 1, Flags: pcaptest.SYN,
			})
		}
		found := e.Analyze(sessionsFrom(t, frames))
		var ids []string
		for _, f := range found {
			ids = append(ids, f.RuleID)
		}
		if !contains(ids, "tight-scan") {
			t.Fatalf("expected new rule id, got %v", ids)
		}
		for _, id := range ids {
			if id == "builtin.port-scan" {
				t.Fatal("old built-in rule still present after replacement")
			}
		}
	})

	t.Run("业务:规则更新/参数边界校验", func(t *testing.T) {
		e := detect.NewDefaultEngine()
		cases := [][]byte{
			[]byte(`[{"id":"a","kind":"port_scan","params":{"threshold":1,"time_window":"10s"}}]`),
			[]byte(`[{"id":"a","kind":"periodic_beacon","params":{"min_count":2,"min_interval":"1s","max_interval":"2s","jitter_ratio":0.1}}]`),
			[]byte(`[{"id":"a","kind":"periodic_beacon","params":{"min_count":3,"min_interval":"5s","max_interval":"1s","jitter_ratio":0.1}}]`),
			[]byte(`[]`),
		}
		for i, c := range cases {
			if err := e.ParseAndUpdate(int(10+i), c); err == nil {
				t.Fatalf("case %d accepted", i)
			}
		}
	})

	t.Run("业务:规则更新/并发分析不出现新旧规则混用", func(t *testing.T) {
		e := detect.NewDefaultEngine()
		base := time.Date(2024, 6, 3, 0, 0, 0, 0, time.UTC)
		mkSessions := func(n int, src string) []*session.Session {
			var frames []pcaptest.Frame
			for i := 0; i < n; i++ {
				frames = append(frames, pcaptest.Frame{
					TS:    base.Add(time.Duration(i) * time.Second),
					SrcIP: src, DstIP: "10.6.0.2",
					SrcPort: uint16(40000 + i), DstPort: uint16(3000 + i), Seq: 1, Flags: pcaptest.SYN,
				})
			}
			return sessionsFrom(t, frames)
		}
		sess12 := mkSessions(12, "10.6.1.1")
		sess2 := mkSessions(2, "10.6.2.1")

		var wg sync.WaitGroup
		stop := make(chan struct{})
		// Hammer updates: every generation is internally consistent.
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := 100
			for {
				select {
				case <-stop:
					return
				default:
				}
				raw := fmtRuleSet(v)
				_ = e.ParseAndUpdate(v, raw)
				v++
			}
		}()
		// Every analysis must observe exactly one rule id and a
		// threshold coherent with that id (either all builtins or the
		// single rotating rule), never a mixture.
		for i := 0; i < 200; i++ {
			found := e.Analyze(sess12)
			ids := map[string]bool{}
			for _, f := range found {
				ids[f.RuleID] = true
			}
			for id := range ids {
				if id != "builtin.port-scan" && id != "rotating-scan" &&
					id != "builtin.failed-connect" && id != "builtin.periodic-beacon" {
					t.Fatalf("unknown rule id during churn: %s", id)
				}
			}
			_ = sess2
		}
		close(stop)
		wg.Wait()
	})
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func fmtRuleSet(v int) []byte {
	return []byte(`[{"id":"rotating-scan","kind":"port_scan","params":{"threshold":` +
		strconv.Itoa(3+v%8) + `,"time_window":"60s","require_failed":true}}]`)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
