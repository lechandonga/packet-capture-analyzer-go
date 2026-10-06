package detect

import (
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/lechandonga/packet-capture-analyzer-go/rules"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

// portAttempt is one initiator SYN with its observed destination.
type portAttempt struct {
	s    *session.Session
	port uint16
	usec int64
}

func attemptsFrom(sessions []*session.Session) map[string][]portAttempt {
	// subject -> attempts; keyed by initiator source IP.
	m := map[string][]portAttempt{}
	for _, s := range sessions {
		if s.Proto != 6 || !s.Attempt {
			continue
		}
		src := ipString(s.Init.IP)
		m[src] = append(m[src], portAttempt{s: s, port: s.Resp.Port, usec: s.FirstUsec})
	}
	return m
}

func detectPortScan(r rules.Rule, version int, sessions []*session.Session) []Finding {
	bySrc := attemptsFrom(sessions)
	var out []Finding
	srcs := make([]string, 0, len(bySrc))
	for k := range bySrc {
		srcs = append(srcs, k)
	}
	sort.Strings(srcs)
	for _, src := range srcs {
		attempts := bySrc[src]
		sort.Slice(attempts, func(i, j int) bool {
			if attempts[i].usec != attempts[j].usec {
				return attempts[i].usec < attempts[j].usec
			}
			return attempts[i].s.ID < attempts[j].s.ID
		})
		// Sliding window over distinct destination ports.
		fired := false
		for i := 0; i < len(attempts) && !fired; i++ {
			ports := map[uint16]portAttempt{}
			var window []portAttempt
			for j := i; j < len(attempts); j++ {
				if attempts[j].usec-attempts[i].usec > r.WindowUsec {
					break
				}
				window = append(window, attempts[j])
				ports[attempts[j].port] = attempts[j]
			}
			if len(ports) >= r.Threshold {
				out = append(out, buildPortFinding(r, version, src, window, ports))
				fired = true
			}
		}
	}
	return out
}

func buildPortFinding(r rules.Rule, version int, src string, window []portAttempt, ports map[uint16]portAttempt) Finding {
	dsts := map[string]struct{}{}
	var ev []Evidence
	var first, last int64 = -1, 0
	for _, a := range window {
		if first < 0 || a.usec < first {
			first = a.usec
		}
		if a.usec > last {
			last = a.usec
		}
		d := ipString(a.s.Resp.IP)
		dsts[d] = struct{}{}
		detail := fmt.Sprintf("SYN %s:%d status=%s", d, a.port, a.s.Status)
		ev = append(ev, Evidence{SessionID: a.s.ID, Flow: src + " -> " + d, TimeUsec: a.usec, Detail: detail})
	}
	dstList := make([]string, 0, len(dsts))
	for d := range dsts {
		dstList = append(dstList, d)
	}
	sort.Strings(dstList)
	return Finding{
		RuleID: r.ID, RuleType: r.Type, RuleVersion: version,
		Severity: SeverityHigh, Subject: src,
		Metric:     fmt.Sprintf("%d distinct destination ports to %d host(s) in window", len(ports), len(dstList)),
		Value:      len(ports),
		WindowUsec: r.WindowUsec, FirstUsec: first, LastUsec: last,
		Evidence: ev,
	}
}

func detectFailedConnect(r rules.Rule, version int, sessions []*session.Session) []Finding {
	type fail struct {
		s    *session.Session
		usec int64
	}
	byPair := map[string][]fail{}
	for _, s := range sessions {
		if s.Proto != 6 || s.Status != session.StatusFailed {
			continue
		}
		src, dst := ipString(s.Init.IP), ipString(s.Resp.IP)
		key := src + " -> " + dst
		byPair[key] = append(byPair[key], fail{s: s, usec: s.FirstUsec})
	}
	keys := make([]string, 0, len(byPair))
	for k := range byPair {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Finding
	for _, key := range keys {
		fails := byPair[key]
		sort.Slice(fails, func(i, j int) bool {
			if fails[i].usec != fails[j].usec {
				return fails[i].usec < fails[j].usec
			}
			return fails[i].s.ID < fails[j].s.ID
		})
		best := 0
		var first, last int64
		var chosen []fail
		for i := 0; i < len(fails); i++ {
			var win []fail
			for j := i; j < len(fails); j++ {
				if fails[j].usec-fails[i].usec > r.WindowUsec {
					break
				}
				win = append(win, fails[j])
			}
			if len(win) > best {
				best = len(win)
				chosen = win
				first, last = win[0].usec, win[len(win)-1].usec
			}
		}
		if best >= r.Threshold {
			ev := make([]Evidence, 0, len(chosen))
			ports := map[uint16]bool{}
			for _, f := range chosen {
				ports[f.s.Resp.Port] = true
				ev = append(ev, Evidence{
					SessionID: f.s.ID, Flow: key, TimeUsec: f.usec,
					Detail: fmt.Sprintf("failed SYN to port %d (RST/no SYN-ACK)", f.s.Resp.Port),
				})
			}
			out = append(out, Finding{
				RuleID: r.ID, RuleType: r.Type, RuleVersion: version,
				Severity: SeverityMedium, Subject: key,
				Metric: fmt.Sprintf("%d failed connections across %d port(s)", best, len(ports)),
				Value:  best, WindowUsec: r.WindowUsec,
				FirstUsec: first, LastUsec: last, Evidence: ev,
			})
		}
	}
	return out
}

func ipString(ip []byte) string {
	if len(ip) == 0 {
		return "?"
	}
	return net.IP(ip).String()
}

func portString(p uint16) string { return ":" + strconv.Itoa(int(p)) }
