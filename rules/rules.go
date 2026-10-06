// Package rules defines the detection rules and an atomic, versioned rule
// store. An update is validated completely before it becomes visible, so a
// concurrent analysis either sees the whole old ruleset or the whole new one.
package rules

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// RuleType identifies a detection rule kind.
type RuleType string

const (
	RulePortScan         RuleType = "port_scan"
	RuleFailedConnect    RuleType = "repeated_failed_connection"
	RulePeriodicOutbound RuleType = "periodic_outbound"
)

// Rule is one detection configuration. Only fields relevant to Type apply.
type Rule struct {
	ID   string   `json:"id"`
	Type RuleType `json:"type"`
	// Enabled lets updates retire a rule without deleting its history.
	Enabled bool `json:"enabled"`

	// Common: consider events within WindowUsec.
	WindowUsec int64 `json:"window_usec"`

	// PortScan: distinct destination ports >= Threshold from one source.
	Threshold int `json:"threshold"`

	// FailedConnect: failed attempts (no SYN-ACK / RST) >= Threshold to one
	// destination IP (any port), within WindowUsec.
	// (uses Threshold + WindowUsec)

	// PeriodicOutbound: >= MinConnections outbound attempts to DstPort from a
	// source with mean inter-connection interval in [MinPeriodUsec,
	// MaxPeriodUsec] and interval coefficient of dispersion <= MaxJitter.
	MinConnections int    `json:"min_connections"`
	MinPeriodUsec  int64  `json:"min_period_usec"`
	MaxPeriodUsec  int64  `json:"max_period_usec"`
	MaxJitterBPS   int    `json:"jitter_bps"` // basis points, e.g. 3000 = 30%
	DstPort        uint16 `json:"dst_port"`
}

// Ruleset is an immutable collection of rules with a monotonic version.
type Ruleset struct {
	Version int
	Rules   []Rule
	byID    map[string]Rule
}

// Get looks up a rule by ID.
func (rs *Ruleset) Get(id string) (Rule, bool) {
	r, ok := rs.byID[id]
	return r, ok
}

// Sorted returns rules sorted by (Type, ID) for deterministic processing.
func (rs *Ruleset) Sorted() []Rule {
	out := append([]Rule(nil), rs.Rules...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Validate checks a ruleset candidate and returns the normalized copy or a
// descriptive error; nothing is published on error.
func Validate(candidate []Rule) ([]Rule, error) {
	if len(candidate) == 0 {
		return nil, errors.New("rules: ruleset must contain at least one rule")
	}
	seen := map[string]bool{}
	out := make([]Rule, len(candidate))
	for i, r := range candidate {
		if r.ID == "" {
			return nil, fmt.Errorf("rules: rule at index %d has empty id", i)
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("rules: duplicate rule id %q", r.ID)
		}
		seen[r.ID] = true
		switch r.Type {
		case RulePortScan, RuleFailedConnect:
			if r.WindowUsec <= 0 {
				return nil, fmt.Errorf("rules: %s window_usec must be > 0", r.ID)
			}
			if r.Threshold < 1 {
				return nil, fmt.Errorf("rules: %s threshold must be >= 1", r.ID)
			}
		case RulePeriodicOutbound:
			if r.MinConnections < 2 {
				return nil, fmt.Errorf("rules: %s min_connections must be >= 2", r.ID)
			}
			if r.MinPeriodUsec <= 0 || r.MaxPeriodUsec <= 0 || r.MinPeriodUsec > r.MaxPeriodUsec {
				return nil, fmt.Errorf("rules: %s period range invalid", r.ID)
			}
			if r.MaxJitterBPS < 0 || r.MaxJitterBPS > 10000 {
				return nil, fmt.Errorf("rules: %s jitter_bps out of range [0,10000]", r.ID)
			}
		default:
			return nil, fmt.Errorf("rules: rule %q has unknown type %q", r.ID, r.Type)
		}
		out[i] = r
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func build(version int, rs []Rule) *Ruleset {
	byID := make(map[string]Rule, len(rs))
	for _, r := range rs {
		if r.Enabled {
			byID[r.ID] = r
		}
	}
	enabled := make([]Rule, 0, len(rs))
	for _, r := range rs {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	return &Ruleset{Version: version, Rules: enabled, byID: byID}
}

// Store publishes immutable rulesets atomically.
type Store struct {
	mu      sync.Mutex
	version int
	cur     atomic.Pointer[Ruleset]
}

// NewStore creates a store with an initial validated ruleset.
func NewStore(initial []Rule) (*Store, error) {
	rs, err := Validate(initial)
	if err != nil {
		return nil, err
	}
	st := &Store{version: 1}
	st.cur.Store(build(1, rs))
	return st, nil
}

// Current returns the active immutable snapshot.
func (s *Store) Current() *Ruleset {
	return s.cur.Load()
}

// Update validates and atomically publishes a new ruleset. On failure the
// previously active ruleset is retained and the returned error explains why.
func (s *Store) Update(candidate []Rule) (*Ruleset, error) {
	rs, err := Validate(candidate)
	if err != nil {
		return s.cur.Load(), err
	}
	s.mu.Lock()
	s.version++
	v := s.version
	s.mu.Unlock()
	next := build(v, rs)
	s.cur.Store(next)
	return next, nil
}

// DefaultRules is the built-in ruleset used when callers provide none.
func DefaultRules() []Rule {
	return []Rule{
		{ID: "builtin.portscan", Type: RulePortScan, Enabled: true, WindowUsec: 10_000_000, Threshold: 20},
		{ID: "builtin.failed-conn", Type: RuleFailedConnect, Enabled: true, WindowUsec: 30_000_000, Threshold: 10},
		{ID: "builtin.periodic-beacon", Type: RulePeriodicOutbound, Enabled: true,
			MinConnections: 5, MinPeriodUsec: 30_000_000, MaxPeriodUsec: 600_000_000,
			MaxJitterBPS: 2500, DstPort: 443},
	}
}
