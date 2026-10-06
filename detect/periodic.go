package detect

import (
	"fmt"
	"math"
	"sort"

	"github.com/lechandonga/packet-capture-analyzer-go/rules"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

type timedHit struct {
	s    *session.Session
	usec int64
}

// detectPeriodic finds a source whose outbound attempts to one destination
// port recur with a stable interval (a beacon). Timing is evaluated on the
// capture packet clock so replays are deterministic.
func detectPeriodic(r rules.Rule, version int, sessions []*session.Session) []Finding {
	byKey := map[string][]timedHit{} // "src -> dst:port"
	for _, s := range sessions {
		if s.Proto != 6 || !s.Attempt {
			continue
		}
		if s.Resp.Port != r.DstPort {
			continue
		}
		key := ipString(s.Init.IP) + " -> " + ipString(s.Resp.IP) + fmt.Sprintf(":%d", r.DstPort)
		byKey[key] = append(byKey[key], timedHit{s: s, usec: s.FirstUsec})
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []Finding
	for _, key := range keys {
		hits := byKey[key]
		sort.Slice(hits, func(i, j int) bool {
			if hits[i].usec != hits[j].usec {
				return hits[i].usec < hits[j].usec
			}
			return hits[i].s.ID < hits[j].s.ID
		})
		if len(hits) < r.MinConnections {
			continue
		}
		// Evaluate every contiguous run >= MinConnections and take the best
		// (lowest dispersion) qualifying run. Deterministic by start index.
		type run struct {
			start, end int
			mean       float64
			codBPS     int
		}
		var best *run
		for i := 0; i+r.MinConnections <= len(hits); i++ {
			for j := i + r.MinConnections; j <= len(hits); j++ {
				iv := intervals(hits[i:j])
				mean, cod := stats(iv)
				if mean < float64(r.MinPeriodUsec) || mean > float64(r.MaxPeriodUsec) {
					continue
				}
				bps := int(math.Round(cod * 10000))
				if bps > r.MaxJitterBPS {
					continue
				}
				cand := run{start: i, end: j, mean: mean, codBPS: bps}
				if best == nil || cand.codBPS < best.codBPS {
					best = &cand
				}
			}
		}
		if best == nil {
			continue
		}
		chosen := hits[best.start:best.end]
		ev := make([]Evidence, 0, len(chosen))
		for _, h := range chosen {
			ev = append(ev, Evidence{
				SessionID: h.s.ID, Flow: key, TimeUsec: h.usec,
				Detail: fmt.Sprintf("outbound attempt #%d status=%s", len(ev)+1, h.s.Status),
			})
		}
		out = append(out, Finding{
			RuleID: r.ID, RuleType: r.Type, RuleVersion: version,
			Severity: SeverityMedium, Subject: key,
			Metric: fmt.Sprintf("mean interval %.2fs, dispersion %d bps over %d connections",
				best.mean/1e6, best.codBPS, len(chosen)),
			Value:     len(chosen),
			FirstUsec: chosen[0].usec, LastUsec: chosen[len(chosen)-1].usec,
			Evidence: ev,
		})
	}
	return out
}

func intervals(hits []timedHit) []float64 {
	out := make([]float64, 0, len(hits)-1)
	for i := 1; i < len(hits); i++ {
		out = append(out, float64(hits[i].usec-hits[i-1].usec))
	}
	return out
}

func stats(xs []float64) (mean, cod float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean = sum / float64(len(xs))
	if mean == 0 {
		return mean, math.Inf(1)
	}
	var sq float64
	for _, x := range xs {
		d := x - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(len(xs)))
	return mean, std / mean
}
