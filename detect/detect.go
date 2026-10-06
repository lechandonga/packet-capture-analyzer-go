// Package detect evaluates reassembled sessions against an immutable ruleset
// snapshot. Findings are deterministic: evidence is sorted by (time, key) and
// a rule version is attached to every conclusion, so concurrent rule updates
// can never mix old and new semantics inside one analysis run.
package detect

import (
	"sort"
	"sync"

	"github.com/lechandonga/packet-capture-analyzer-go/rules"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

// Severity levels.
type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Evidence points at one supporting session.
type Evidence struct {
	SessionID int64  `json:"session_id"`
	Flow      string `json:"flow"`
	TimeUsec  int64  `json:"time_usec"`
	Detail    string `json:"detail"`
}

// Finding is one rule conclusion with fully traceable evidence.
type Finding struct {
	RuleID      string         `json:"rule_id"`
	RuleType    rules.RuleType `json:"rule_type"`
	RuleVersion int            `json:"rule_version"`
	Severity    Severity       `json:"severity"`
	Subject     string         `json:"subject"` // e.g. source IP
	Metric      string         `json:"metric"`  // human-readable metric
	Value       int            `json:"value"`
	WindowUsec  int64          `json:"window_usec"`
	FirstUsec   int64          `json:"first_usec"`
	LastUsec    int64          `json:"last_usec"`
	Evidence    []Evidence     `json:"evidence"`
}

// Detector accumulates sessions and evaluates a pinned ruleset snapshot.
type Detector struct {
	snapshot *rules.Ruleset
	mu       sync.Mutex
	sessions []*session.Session
}

// New pins the ruleset that all subsequent Observe/Finalize calls will use.
func New(rs *rules.Ruleset) *Detector {
	return &Detector{snapshot: rs}
}

// RuleVersion reports the pinned snapshot version.
func (d *Detector) RuleVersion() int { return d.snapshot.Version }

// Observe records one session (typically as the session engine finalises it).
func (d *Detector) Observe(s *session.Session) {
	d.mu.Lock()
	d.sessions = append(d.sessions, s)
	d.mu.Unlock()
}

// Finalize evaluates all observations and returns deterministic findings.
func (d *Detector) Finalize() []Finding {
	d.mu.Lock()
	sessions := append([]*session.Session(nil), d.sessions...)
	d.mu.Unlock()

	var findings []Finding
	for _, r := range d.snapshot.Sorted() {
		switch r.Type {
		case rules.RulePortScan:
			findings = append(findings, detectPortScan(r, d.snapshot.Version, sessions)...)
		case rules.RuleFailedConnect:
			findings = append(findings, detectFailedConnect(r, d.snapshot.Version, sessions)...)
		case rules.RulePeriodicOutbound:
			findings = append(findings, detectPeriodic(r, d.snapshot.Version, sessions)...)
		}
	}
	sortFindings(findings)
	return findings
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].RuleID != f[j].RuleID {
			return f[i].RuleID < f[j].RuleID
		}
		if f[i].Subject != f[j].Subject {
			return f[i].Subject < f[j].Subject
		}
		return f[i].FirstUsec < f[j].FirstUsec
	})
	for i := range f {
		ev := f[i].Evidence
		sort.SliceStable(ev, func(a, b int) bool {
			if ev[a].TimeUsec != ev[b].TimeUsec {
				return ev[a].TimeUsec < ev[b].TimeUsec
			}
			return ev[a].SessionID < ev[b].SessionID
		})
		f[i].Evidence = ev
	}
}

func epString(e session.Endpoint) string {
	return ipString(e.IP) + portString(e.Port)
}
