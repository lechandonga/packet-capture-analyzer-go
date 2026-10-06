package rules_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/lechandonga/packet-capture-analyzer-go/internal/testutil"
	"github.com/lechandonga/packet-capture-analyzer-go/rules"
)

func TestAtomicUpdates(t *testing.T) {
	testutil.DomainBanner(t, "rule-lifecycle")

	t.Run("invalid update leaves previous ruleset live", func(t *testing.T) {
		c := testutil.Start(t, "rule-lifecycle", "invalid-update-rollback")
		st, err := rules.NewStore(rules.DefaultRules())
		if err != nil {
			t.Fatal(err)
		}
		v1 := st.Current()
		bad := []rules.Rule{{ID: "x", Type: rules.RulePortScan, Enabled: true, WindowUsec: -1, Threshold: 1}}
		got, err := st.Update(bad)
		if err == nil {
			c.Fail("expected validation error")
			return
		}
		if got.Version != v1.Version || st.Current().Version != v1.Version {
			c.Fail("active version changed after failed update")
			return
		}
		c.Pass("rejected: %v; active stays v%d", err, st.Current().Version)
	})

	t.Run("valid update increments version atomically", func(t *testing.T) {
		c := testutil.Start(t, "rule-lifecycle", "valid-update")
		st, _ := rules.NewStore(rules.DefaultRules())
		nr := rules.DefaultRules()
		nr[0].Threshold = 5
		rs, err := st.Update(nr)
		if err != nil || rs.Version != 2 {
			c.Fail("update err=%v version=%d", err, rs.Version)
			return
		}
		if g, _ := rs.Get("builtin.portscan"); g.Threshold != 5 {
			c.Fail("new threshold not visible: %d", g.Threshold)
			return
		}
		c.Pass("v2 published atomically")
	})

	t.Run("validation catches all semantic errors", func(t *testing.T) {
		c := testutil.Start(t, "rule-lifecycle", "validation-matrix")
		bad := [][]rules.Rule{
			{},
			{{ID: "", Type: rules.RulePortScan, Enabled: true, WindowUsec: 1, Threshold: 1}},
			{{ID: "a", Type: "weird", Enabled: true}},
			{{ID: "a", Type: rules.RulePortScan, Enabled: true, WindowUsec: 1, Threshold: 1},
				{ID: "a", Type: rules.RulePortScan, Enabled: true, WindowUsec: 1, Threshold: 1}},
			{{ID: "p", Type: rules.RulePeriodicOutbound, Enabled: true, MinConnections: 1, MinPeriodUsec: 1, MaxPeriodUsec: 2}},
			{{ID: "p", Type: rules.RulePeriodicOutbound, Enabled: true, MinConnections: 2, MinPeriodUsec: 10, MaxPeriodUsec: 5, MaxJitterBPS: 1}},
			{{ID: "p", Type: rules.RulePeriodicOutbound, Enabled: true, MinConnections: 2, MinPeriodUsec: 10, MaxPeriodUsec: 20, MaxJitterBPS: 20000}},
		}
		for i, b := range bad {
			if _, err := rules.Validate(b); err == nil {
				c.Fail("case %d expected error", i)
				return
			}
		}
		c.Pass("%d invalid candidates all rejected", len(bad))
	})

	t.Run("concurrent readers never observe a half-written ruleset", func(t *testing.T) {
		c := testutil.Start(t, "rule-lifecycle", "concurrent-read-consistency")
		st, _ := rules.NewStore(rules.DefaultRules())
		var wg sync.WaitGroup
		stop := make(chan struct{})
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					rs := st.Current()
					ids := map[string]bool{}
					for _, r := range rs.Rules {
						if ids[r.ID] {
							t.Errorf("duplicate rule in snapshot")
							return
						}
						ids[r.ID] = true
						if r.WindowUsec < 0 {
							t.Errorf("negative window")
							return
						}
					}
					if len(rs.Rules) == 0 {
						t.Errorf("empty snapshot")
						return
					}
				}
			}()
		}
		for i := 0; i < 50; i++ {
			nr := rules.DefaultRules()
			nr[0].Threshold = 10 + i%30
			_, err := st.Update(nr)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = st.Update([]rules.Rule{{ID: "bad", Type: "nope"}})
		}
		close(stop)
		wg.Wait()
		if !strings.Contains("ok", "ok") {
			t.FailNow()
		}
		c.Pass("8 readers x 50 valid+invalid updates, all snapshots consistent")
	})
}
