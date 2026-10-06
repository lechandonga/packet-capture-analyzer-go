package analyzer_test

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lechandonga/packet-capture-analyzer-go/analyzer"
	"github.com/lechandonga/packet-capture-analyzer-go/internal/pcapgen"
	"github.com/lechandonga/packet-capture-analyzer-go/internal/testutil"
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
	"github.com/lechandonga/packet-capture-analyzer-go/rules"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

func scanCapture(ports int) []byte {
	var src = [4]byte{10, 0, 0, 9}
	var dst = [4]byte{10, 1, 1, 1}
	b := pcapgen.New()
	for port := uint16(1); port <= uint16(ports); port++ {
		u := uint32(port) * 10000
		b.AddAt(u, pcapgen.EthIP4TCP([6]byte{1}, [6]byte{2}, src, dst, uint16(30000+port), port, 1, 0, pcap.TCPSyn, nil))
		b.AddAt(u+100, pcapgen.EthIP4TCP([6]byte{2}, [6]byte{1}, dst, src, port, uint16(30000+port), 1, 1, pcap.TCPRst|pcap.TCPAck, nil))
	}
	return b.Bytes()
}

func TestBatchIsolationAndDeterminism(t *testing.T) {
	testutil.DomainBanner(t, "batch-analysis")
	dir := t.TempDir()
	files := map[string][]byte{
		"good1.pcap":    scanCapture(25),
		"good2.pcap":    scanCapture(30),
		"trunc.pcap":    scanCapture(10)[:40], // truncated mid-record
		"badmagic.pcap": {0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0},
		"empty.pcap":    {},
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var paths []string
	for n := range files {
		paths = append(paths, filepath.Join(dir, n))
	}

	t.Run("one corrupt file does not affect the others", func(t *testing.T) {
		c := testutil.Start(t, "batch-analysis", "per-file-isolation")
		a, err := analyzer.New(nil, session.Config{})
		if err != nil {
			t.Fatal(err)
		}
		rep := a.AnalyzeBatch(paths)
		if len(rep.Results) != len(files) {
			c.Fail("got %d results, want %d", len(rep.Results), len(files))
			return
		}
		byName := map[string]analyzer.FileResult{}
		for _, r := range rep.Results {
			byName[filepath.Base(r.Path)] = r
		}
		if byName["good1.pcap"].Error != nil || len(byName["good1.pcap"].Findings) == 0 {
			c.Fail("good1 should analyze cleanly: %+v", byName["good1.pcap"].Error)
			return
		}
		if byName["good2.pcap"].Error != nil {
			c.Fail("good2 should analyze cleanly")
			return
		}
		if byName["trunc.pcap"].Error == nil || byName["trunc.pcap"].Error.Kind == "" {
			c.Fail("trunc.pcap must report classified error")
			return
		}
		if byName["badmagic.pcap"].Error.Kind != pcap.KindBadMagic {
			c.Fail("badmagic kind=%v", byName["badmagic.pcap"].Error)
			return
		}
		if byName["empty.pcap"].Error.Kind != pcap.KindTruncatedHeader {
			c.Fail("empty kind=%v", byName["empty.pcap"].Error)
			return
		}
		c.Pass("5 files: 2 good analyzed, 3 corrupt classified independently")
	})

	t.Run("repeated parsing yields identical conclusions", func(t *testing.T) {
		c := testutil.Start(t, "batch-analysis", "deterministic-replay")
		a, _ := analyzer.New(nil, session.Config{})
		first := a.AnalyzeBytes("good1.pcap", files["good1.pcap"])
		second := a.AnalyzeBytes("good1.pcap", files["good1.pcap"])
		if len(first.Findings) != len(second.Findings) {
			c.Fail("finding counts differ: %d vs %d", len(first.Findings), len(second.Findings))
			return
		}
		for i := range first.Findings {
			if first.Findings[i].Metric != second.Findings[i].Metric ||
				len(first.Findings[i].Evidence) != len(second.Findings[i].Evidence) {
				c.Fail("finding %d differs", i)
				return
			}
		}
		c.Pass("two independent runs produced %d identical findings", len(first.Findings))
	})
}

func TestConcurrentAnalysisWithRuleUpdates(t *testing.T) {
	testutil.DomainBanner(t, "concurrency")
	c := testutil.Start(t, "concurrency", "analysis-vs-atomic-update")

	st, err := rules.NewStore(rules.DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	data := scanCapture(25)

	stop := make(chan struct{})
	var workerWg sync.WaitGroup
	var updaterWg sync.WaitGroup
	updaterWg.Add(1)
	go func() {
		defer updaterWg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			nr := rules.DefaultRules()
			nr[0].Threshold = 5 + i%40
			if _, err := st.Update(nr); err != nil {
				t.Errorf("valid update rejected: %v", err)
				return
			}
			if _, err := st.Update([]rules.Rule{{ID: "bad", Type: "nope"}}); err == nil {
				t.Error("invalid update accepted")
				return
			}
		}
	}()
	violations := 0
	var mu sync.Mutex
	for w := 0; w < 16; w++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			a, _ := analyzer.New(st, session.Config{})
			for i := 0; i < 25; i++ {
				res := a.AnalyzeBytes("capture.pcap", data)
				v := res.RuleVersion
				for _, f := range res.Findings {
					if f.RuleVersion != v {
						mu.Lock()
						violations++
						mu.Unlock()
						return
					}
				}
			}
		}()
	}
	workerWg.Wait()
	close(stop)
	updaterWg.Wait()
	if violations != 0 {
		c.Fail("%d findings mixed rule versions", violations)
		return
	}
	c.Pass("16 analyzers vs continuous updates; no mixed-version conclusions")
}
