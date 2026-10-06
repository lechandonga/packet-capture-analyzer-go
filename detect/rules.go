// Package detect evaluates reassembled sessions against an atomic,
// versioned rule set. Rule replacement is all-or-nothing: an in-flight
// analysis always sees one complete generation of rules, never a mix.
package detect

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// RuleKind enumerates the built-in behavior checks.
type RuleKind string

const (
	RulePortScan       RuleKind = "port_scan"
	RuleFailedConnect  RuleKind = "failed_connection_burst"
	RulePeriodicBeacon RuleKind = "periodic_beacon"
)

// Rule is one configurable detection check.
type Rule struct {
	ID          string          `json:"id"`
	Kind        RuleKind        `json:"kind"`
	Description string          `json:"description,omitempty"`
	Params      json.RawMessage `json:"params,omitempty"`
}

// PortScanParams triggers when one source contacts at least Threshold
// distinct destination ports (optionally restricted to DstCIDRs) and the
// majority of those attempts never completed the handshake.
type PortScanParams struct {
	Threshold     int      `json:"threshold"`
	TimeWindow    Duration `json:"time_window"`
	RequireFailed bool     `json:"require_failed"`
	Ports         []uint16 `json:"ports,omitempty"` // empty = any port
}

// FailedConnectParams triggers when one source accumulates at least
// Threshold failed/refused connections toward one destination host.
type FailedConnectParams struct {
	Threshold  int      `json:"threshold"`
	TimeWindow Duration `json:"time_window"`
}

// PeriodicBeaconParams triggers when a source opens at least MinCount
// connections to one (host, port) with inter-arrival intervals whose
// jitter stays within JitterRatio of the mean (e.g. 0.1 = 10%).
type PeriodicBeaconParams struct {
	MinCount    int      `json:"min_count"`
	MinInterval Duration `json:"min_interval"`
	MaxInterval Duration `json:"max_interval"`
	JitterRatio float64  `json:"jitter_ratio"`
}

// Duration is a JSON-friendly time.Duration ("30s", "5m").
type Duration time.Duration

func (d Duration) Std() time.Duration { return time.Duration(d) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

// DefaultRules returns the built-in rule set.
func DefaultRules() []Rule {
	must := func(b []byte) json.RawMessage { return b }
	return []Rule{
		{
			ID: "builtin.port-scan", Kind: RulePortScan,
			Description: "one source contacts many distinct ports in a short window",
			Params:      must(mustJSON(PortScanParams{Threshold: 10, TimeWindow: Duration(30 * time.Second), RequireFailed: true})),
		},
		{
			ID: "builtin.failed-connect", Kind: RuleFailedConnect,
			Description: "repeated failed/refused connections to one host",
			Params:      must(mustJSON(FailedConnectParams{Threshold: 5, TimeWindow: Duration(time.Minute)})),
		},
		{
			ID: "builtin.periodic-beacon", Kind: RulePeriodicBeacon,
			Description: "periodic outbound reconnections to the same service",
			Params: must(mustJSON(PeriodicBeaconParams{
				MinCount: 4, MinInterval: Duration(5 * time.Second),
				MaxInterval: Duration(time.Hour), JitterRatio: 0.1,
			})),
		},
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// Validate checks a rule set structurally and returns the first problem.
func Validate(rules []Rule) error {
	seen := map[string]bool{}
	if len(rules) == 0 {
		return fmt.Errorf("rule set must not be empty")
	}
	for i, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("rule #%d: missing id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		switch r.Kind {
		case RulePortScan:
			var p PortScanParams
			if err := unmarshalParams(r.Params, &p); err != nil {
				return fmt.Errorf("rule %q: %w", r.ID, err)
			}
			if p.Threshold < 2 {
				return fmt.Errorf("rule %q: threshold must be >= 2", r.ID)
			}
		case RuleFailedConnect:
			var p FailedConnectParams
			if err := unmarshalParams(r.Params, &p); err != nil {
				return fmt.Errorf("rule %q: %w", r.ID, err)
			}
			if p.Threshold < 2 {
				return fmt.Errorf("rule %q: threshold must be >= 2", r.ID)
			}
		case RulePeriodicBeacon:
			var p PeriodicBeaconParams
			if err := unmarshalParams(r.Params, &p); err != nil {
				return fmt.Errorf("rule %q: %w", r.ID, err)
			}
			if p.MinCount < 3 {
				return fmt.Errorf("rule %q: min_count must be >= 3", r.ID)
			}
			if p.MinInterval <= 0 || p.MaxInterval < p.MinInterval {
				return fmt.Errorf("rule %q: invalid interval bounds", r.ID)
			}
			if p.JitterRatio <= 0 || p.JitterRatio > 1 {
				return fmt.Errorf("rule %q: jitter_ratio must be within (0,1]", r.ID)
			}
		default:
			return fmt.Errorf("rule %q: unknown kind %q", r.ID, r.Kind)
		}
	}
	return nil
}

func unmarshalParams(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return fmt.Errorf("missing params")
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return err
	}
	return nil
}

// RuleSet is one immutable generation of rules.
type RuleSet struct {
	Version int
	Rules   []Rule
}

// Finding is one rule hit.
type Finding struct {
	RuleID   string
	Kind     RuleKind
	Severity string
	Summary  string
	Evidence Evidence
}

// Evidence carries the deterministic data behind a finding.
type Evidence struct {
	Source        string
	Destination   string
	Port          uint16
	Count         int
	DistinctPorts []uint16
	SessionKeys   []string
	FirstSeen     string // RFC3339 UTC
	LastSeen      string
	MeanInterval  string
}

func sortedPorts(m map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
