package detect

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync/atomic"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

// Engine holds the currently active, immutable rule generation. Analyses
// take a pointer snapshot at entry, so a concurrent Update can never make
// them observe half-old / half-new rules.
type Engine struct {
	rules atomic.Pointer[compiledSet]
}

type compiledSet struct {
	rs       RuleSet
	compiled []compiledRule
}

type compiledRule struct {
	rule Rule
	run  func([]*session.Session) []Finding
}

// NewEngine builds an engine with explicit rules.
func NewEngine(rules []Rule) (*Engine, error) {
	e := &Engine{}
	if err := e.Update(1, rules); err != nil {
		return nil, err
	}
	return e, nil
}

// NewDefaultEngine builds an engine with the built-in rules.
func NewDefaultEngine() *Engine {
	e := &Engine{}
	if err := e.Update(1, DefaultRules()); err != nil {
		panic(err)
	}
	return e
}

// ActiveVersion returns the generation number currently in effect.
func (e *Engine) ActiveVersion() int {
	cs := e.rules.Load()
	if cs == nil {
		return 0
	}
	return cs.rs.Version
}

// Update validates and installs a whole rule generation atomically. On
// validation failure the previous set stays active; nothing is partially
// applied.
func (e *Engine) Update(version int, rules []Rule) error {
	if version <= 0 {
		return fmt.Errorf("version must be positive")
	}
	if err := Validate(rules); err != nil {
		return err
	}
	cs := &compiledSet{rs: RuleSet{Version: version, Rules: rules}}
	for _, r := range rules {
		cs.compiled = append(cs.compiled, compiledRule{rule: r, run: compileRule(r)})
	}
	e.rules.Store(cs)
	return nil
}

// ParseAndUpdate parses JSON rules then performs an atomic update.
func (e *Engine) ParseAndUpdate(version int, raw []byte) error {
	var rules []Rule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return fmt.Errorf("rule json: %w", err)
	}
	return e.Update(version, rules)
}

// Analyze runs every active rule against the sessions. The output is
// sorted deterministically and identical for identical inputs.
func (e *Engine) Analyze(sessions []*session.Session) []Finding {
	cs := e.rules.Load()
	if cs == nil {
		return nil
	}
	var out []Finding
	for _, c := range cs.compiled {
		out = append(out, c.run(sessions)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return findingKey(out[i]) < findingKey(out[j])
	})
	return out
}

func findingKey(f Finding) string {
	return f.Evidence.Source + "|" + f.Evidence.Destination + "|" +
		fmt.Sprint(f.Evidence.Port)
}

func compileRule(r Rule) func([]*session.Session) []Finding {
	switch r.Kind {
	case RulePortScan:
		var p PortScanParams
		_ = json.Unmarshal(r.Params, &p)
		return func(ss []*session.Session) []Finding { return portScan(r, p, ss) }
	case RuleFailedConnect:
		var p FailedConnectParams
		_ = json.Unmarshal(r.Params, &p)
		return func(ss []*session.Session) []Finding { return failedBurst(r, p, ss) }
	case RulePeriodicBeacon:
		var p PeriodicBeaconParams
		_ = json.Unmarshal(r.Params, &p)
		return func(ss []*session.Session) []Finding { return periodic(r, p, ss) }
	default:
		return nil
	}
}

type attempt struct {
	ts      time.Time
	port    uint16
	dst     string
	failed  bool
	sessKey string
}

func attemptsFrom(s *session.Session) (string, []attempt) {
	return s.Client.Addr, []attempt{{
		ts:      s.FirstTS,
		port:    s.Server.Port,
		dst:     s.Server.Addr,
		failed:  s.Status == session.StatusFailed || s.Status == session.StatusReset,
		sessKey: s.Flow.String(),
	}}
}

func portScan(rule Rule, p PortScanParams, ss []*session.Session) []Finding {
	type agg struct{ atts []attempt }
	bySrc := map[string]*agg{}
	for _, s := range ss {
		if s.UDP {
			continue
		}
		if len(p.Ports) > 0 && !containsPort(p.Ports, s.Server.Port) {
			continue
		}
		src, atts := attemptsFrom(s)
		a := bySrc[src]
		if a == nil {
			a = &agg{}
			bySrc[src] = a
		}
		a.atts = append(a.atts, atts[0])
	}
	srcs := make([]string, 0, len(bySrc))
	for src := range bySrc {
		srcs = append(srcs, src)
	}
	sort.Strings(srcs)
	var out []Finding
	for _, src := range srcs {
		atts := bySrc[src].atts
		sort.Slice(atts, func(i, j int) bool {
			if !atts[i].ts.Equal(atts[j].ts) {
				return atts[i].ts.Before(atts[j].ts)
			}
			return atts[i].port < atts[j].port
		})
		best, first, last, ports := bestWindowPorts(atts, p.TimeWindow.Std())
		if best < p.Threshold {
			continue
		}
		failed := countFailedInWindow(atts, first, last)
		if p.RequireFailed && failed*2 < best {
			continue
		}
		out = append(out, Finding{
			RuleID: rule.ID, Kind: rule.Kind, Severity: "high",
			Summary: fmt.Sprintf("%s contacted %d distinct ports within %s",
				src, best, p.TimeWindow.Std()),
			Evidence: Evidence{
				Source: src, Count: best, DistinctPorts: sortedPorts(ports),
				FirstSeen:   first.UTC().Format(time.RFC3339Nano),
				LastSeen:    last.UTC().Format(time.RFC3339Nano),
				SessionKeys: keysInWindow(atts, first, last),
			},
		})
	}
	return out
}

func bestWindowPorts(atts []attempt, window time.Duration) (int, time.Time, time.Time, map[uint16]bool) {
	best := 0
	var first, last time.Time
	var bestPorts map[uint16]bool
	for i := range atts {
		ports := map[uint16]bool{}
		j := i
		for j < len(atts) && atts[j].ts.Sub(atts[i].ts) <= window {
			ports[atts[j].port] = true
			j++
		}
		if len(ports) > best {
			best = len(ports)
			first, last = atts[i].ts, atts[j-1].ts
			bestPorts = clonePorts(ports)
		}
	}
	return best, first, last, bestPorts
}

func inWindow(ts, first, last time.Time) bool {
	return (ts.After(first) || ts.Equal(first)) && (ts.Before(last) || ts.Equal(last))
}

func countFailedInWindow(atts []attempt, first, last time.Time) int {
	n := 0
	for _, at := range atts {
		if inWindow(at.ts, first, last) && at.failed {
			n++
		}
	}
	return n
}

func keysInWindow(atts []attempt, first, last time.Time) []string {
	seen := map[string]bool{}
	for _, at := range atts {
		if inWindow(at.ts, first, last) {
			seen[at.sessKey] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type srcDst struct{ src, dst string }

func failedBurst(rule Rule, p FailedConnectParams, ss []*session.Session) []Finding {
	group := map[srcDst][]attempt{}
	for _, s := range ss {
		if s.UDP {
			continue
		}
		if s.Status != session.StatusFailed && s.Status != session.StatusReset {
			continue
		}
		src, atts := attemptsFrom(s)
		k := srcDst{src, atts[0].dst}
		group[k] = append(group[k], atts[0])
	}
	var out []Finding
	for _, k := range sortedGroupKeys(group) {
		atts := group[k]
		sort.Slice(atts, func(i, j int) bool {
			if !atts[i].ts.Equal(atts[j].ts) {
				return atts[i].ts.Before(atts[j].ts)
			}
			return atts[i].sessKey < atts[j].sessKey
		})
		bestN := 0
		var f, l time.Time
		for i := range atts {
			j := i
			for j < len(atts) && atts[j].ts.Sub(atts[i].ts) <= p.TimeWindow.Std() {
				j++
			}
			if j-i > bestN {
				bestN = j - i
				f, l = atts[i].ts, atts[j-1].ts
			}
		}
		if bestN < p.Threshold {
			continue
		}
		out = append(out, Finding{
			RuleID: rule.ID, Kind: rule.Kind, Severity: "medium",
			Summary: fmt.Sprintf("%s made %d failed connections to %s within %s",
				k.src, bestN, k.dst, p.TimeWindow.Std()),
			Evidence: Evidence{
				Source:      k.src,
				Destination: k.dst,
				Count:       bestN,
				FirstSeen:   f.UTC().Format(time.RFC3339Nano),
				LastSeen:    l.UTC().Format(time.RFC3339Nano),
				SessionKeys: keysInWindow(atts, f, l),
			},
		})
	}
	return out
}

type beaconKey struct {
	src, dst string
	port     uint16
}

func periodic(rule Rule, p PeriodicBeaconParams, ss []*session.Session) []Finding {
	group := map[beaconKey][]time.Time{}
	sessKeys := map[beaconKey][]string{}
	for _, s := range ss {
		if s.UDP {
			continue
		}
		k := beaconKey{s.Client.Addr, s.Server.Addr, s.Server.Port}
		group[k] = append(group[k], s.FirstTS)
		sessKeys[k] = append(sessKeys[k], s.Flow.String())
	}
	var out []Finding
	for _, k := range sortedBeaconKeys(group) {
		ts := group[k]
		if len(ts) < p.MinCount {
			continue
		}
		sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
		n := len(ts) - 1
		intervals := make([]float64, n)
		var sum float64
		ok := true
		for i := 0; i < n; i++ {
			d := ts[i+1].Sub(ts[i])
			intervals[i] = float64(d)
			sum += float64(d)
			if d < p.MinInterval.Std() || d > p.MaxInterval.Std() {
				ok = false
			}
		}
		if !ok {
			continue
		}
		mean := sum / float64(n)
		if mean <= 0 {
			continue
		}
		var sd float64
		for _, v := range intervals {
			sd += (v - mean) * (v - mean)
		}
		cv := math.Sqrt(sd/float64(n)) / mean
		if cv > p.JitterRatio {
			continue
		}
		sk := append([]string(nil), sessKeys[k]...)
		sort.Strings(sk)
		out = append(out, Finding{
			RuleID: rule.ID, Kind: rule.Kind, Severity: "medium",
			Summary: fmt.Sprintf("%s periodically reconnects to %s:%d (every %s, cv=%.3f)",
				k.src, k.dst, k.port, time.Duration(mean).Round(time.Millisecond), cv),
			Evidence: Evidence{
				Source:       k.src,
				Destination:  k.dst,
				Port:         k.port,
				Count:        len(ts),
				FirstSeen:    ts[0].UTC().Format(time.RFC3339Nano),
				LastSeen:     ts[len(ts)-1].UTC().Format(time.RFC3339Nano),
				MeanInterval: time.Duration(mean).Round(time.Millisecond).String(),
				SessionKeys:  sk,
			},
		})
	}
	return out
}

func containsPort(ports []uint16, want uint16) bool {
	i := sort.Search(len(ports), func(i int) bool { return ports[i] >= want })
	return i < len(ports) && ports[i] == want
}

func clonePorts(m map[uint16]bool) map[uint16]bool {
	out := make(map[uint16]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sortedGroupKeys(m map[srcDst][]attempt) []srcDst {
	out := make([]srcDst, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].src != out[j].src {
			return out[i].src < out[j].src
		}
		return out[i].dst < out[j].dst
	})
	return out
}

func sortedBeaconKeys(m map[beaconKey][]time.Time) []beaconKey {
	out := make([]beaconKey, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.src != b.src {
			return a.src < b.src
		}
		if a.dst != b.dst {
			return a.dst < b.dst
		}
		return a.port < b.port
	})
	return out
}
