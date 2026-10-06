package session

import (
	"sort"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/proto"
)

// Assembler is extended in session.go; this file holds feeding logic.

// HandlePacket feeds one decoded transport packet into the table.
func (a *Assembler) HandlePacket(p *proto.Packet, ts time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ts.After(a.now) {
		a.now = ts
	}
	src := Endpoint{Addr: p.IP.Src, Port: srcPort(p)}
	dst := Endpoint{Addr: p.IP.Dst, Port: dstPort(p)}
	ea, eb := canon(src, dst)
	id := FlowID{Proto: p.IP.Protocol, A: ea, B: eb}

	tr, ok := a.table[id]
	if !ok {
		sess := &Session{Flow: id, FirstTS: ts, LastTS: ts,
			Client: src, Server: dst, UDP: p.UDP != nil}
		tr = &tracked{
			Session: sess,
			c2s:     newStream(&sess.C2SPayload, a.cfg.MaxPayloadPerDirection, &sess.C2S),
			s2c:     newStream(&sess.S2CPayload, a.cfg.MaxPayloadPerDirection, &sess.S2C),
		}
		a.table[id] = tr
		a.enforceMaxLocked()
	}
	sess := tr.Session
	sess.LastTS = ts
	sess.Packets++

	if p.UDP != nil {
		// UDP has no sequence space; count unique datagram payload.
		dir := a.dirStreams(tr, sess, src)
		dir.stats.Packets++
		dir.stats.DataPackets++
		dir.stats.UniqueBytes += int64(len(p.Payload))
		if int64(len(*dir.out)) < dir.maxStored {
			room := dir.maxStored - int64(len(*dir.out))
			if int64(len(p.Payload)) <= room {
				*dir.out = append(*dir.out, p.Payload...)
			} else {
				*dir.out = append(*dir.out, p.Payload[:room]...)
			}
		}
		a.classifyLocked(tr)
		a.reapIdleLocked()
		return
	}

	t := p.TCP
	dir := a.dirStreams(tr, sess, src)

	switch {
	case t.Flags.Has(proto.TCPRst):
		dir.addRST()
	case t.Flags.Has(proto.TCPSyn) && t.Flags.Has(proto.TCPAck):
		sess.SynAckSeen = true
		dir.addSYN(t.Seq)
	case t.Flags.Has(proto.TCPSyn):
		sess.SynSeen = true
		dir.addSYN(t.Seq)
	case t.Flags.Has(proto.TCPFin):
		if len(p.Payload) > 0 {
			dir.addPayload(t.Seq, p.Payload)
		}
		dir.addFIN(t.Seq, len(p.Payload))
	default:
		dir.addPayload(t.Seq, p.Payload)
	}

	if sess.SynSeen && sess.SynAckSeen {
		sess.Established = true
	}

	a.classifyLocked(tr)
	a.reapIdleLocked()
}

func srcPort(p *proto.Packet) uint16 {
	if p.TCP != nil {
		return p.TCP.SrcPort
	}
	return p.UDP.SrcPort
}

func dstPort(p *proto.Packet) uint16 {
	if p.TCP != nil {
		return p.TCP.DstPort
	}
	return p.UDP.DstPort
}

// dir wraps one direction's output and counters.
type dirRef struct {
	out       *[]byte
	maxStored int64
	stats     *DirectionStats
}

func (a *Assembler) dirStreams(tr *tracked, sess *Session, src Endpoint) *stream {
	if src == sess.Client {
		return tr.c2s
	}
	// Client/server can only flip for a pure-ACK direction before the
	// SYN was seen; canonical identity stays fixed.
	if !sess.SynSeen {
		sess.Client = src
		sess.Server = other(sess.Flow, src)
		return tr.c2s
	}
	return tr.s2c
}

func other(f FlowID, e Endpoint) Endpoint {
	if f.A == e {
		return f.B
	}
	return f.A
}

func (a *Assembler) classifyLocked(tr *tracked) {
	sess := tr.Session
	if sess.UDP {
		if sess.Status == StatusOngoing || sess.Status == "" {
			sess.Status = StatusOngoing
		}
		return
	}
	c2sHoles := tr.c2s.holes()
	s2cHoles := tr.s2c.holes()
	sess.Gaps = annotateGaps(c2sHoles, s2cHoles)

	switch {
	case tr.c2s.rst || tr.s2c.rst:
		sess.Status = StatusReset
	case tr.c2s.cleanClosed() && tr.s2c.cleanClosed():
		sess.Status = StatusClosed
	case (tr.c2s.finSet || tr.s2c.finSet) && (len(c2sHoles)+len(s2cHoles) > 0):
		sess.Status = StatusClosedGapped
	case !sess.SynSeen:
		sess.Status = StatusIncomplete
	case sess.SynSeen && !sess.SynAckSeen:
		sess.Status = StatusFailed
	default:
		sess.Status = StatusOngoing
	}
}

func annotateGaps(c2s, s2c []Gap) []Gap {
	out := make([]Gap, 0, len(c2s)+len(s2c))
	for _, g := range c2s {
		g.FromClient = true
		out = append(out, g)
	}
	for _, g := range s2c {
		g.FromClient = false
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FromClient != out[j].FromClient {
			return out[i].FromClient
		}
		return out[i].StartSeq < out[j].StartSeq
	})
	return out
}

// Flush ends a capture: every live session receives its final
// classification (ongoing TCP becomes incomplete) and is removed. The
// returned slice is sorted by first timestamp then flow for stability.
func (a *Assembler) Flush() []*Session {
	a.mu.Lock()
	defer a.mu.Unlock()

	out := make([]*Session, 0, len(a.table))
	for _, tr := range a.table {
		a.classifyLocked(tr)
		sess := tr.Session
		if !sess.UDP && sess.Status == StatusOngoing {
			sess.Status = StatusIncomplete
		}
		if !sess.UDP && sess.Status == "" {
			sess.Status = StatusIncomplete
		}
		out = append(out, sess)
	}
	a.table = map[FlowID]*tracked{}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstTS.Equal(out[j].FirstTS) {
			return out[i].FirstTS.Before(out[j].FirstTS)
		}
		return out[i].Flow.String() < out[j].Flow.String()
	})
	return out
}

// Sessions returns a snapshot copy of session views without removing them.
func (a *Assembler) Sessions() []*Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*Session, 0, len(a.table))
	for _, tr := range a.table {
		a.classifyLocked(tr)
		out = append(out, tr.Session)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].FirstTS.Equal(out[j].FirstTS) {
			return out[i].FirstTS.Before(out[j].FirstTS)
		}
		return out[i].Flow.String() < out[j].Flow.String()
	})
	return out
}

func (a *Assembler) reapIdleLocked() {
	for id, tr := range a.table {
		var deadline time.Time
		switch {
		case isFinished(tr.Status):
			ret := a.cfg.CompletedRetention
			if ret == 0 {
				ret = 30 * time.Second
			}
			if ret >= 0 {
				deadline = a.now.Add(-ret)
			}
		case a.cfg.IdleTimeout > 0:
			deadline = a.now.Add(-a.cfg.IdleTimeout)
		default:
			continue
		}
		if !deadline.IsZero() && tr.LastTS.Before(deadline) {
			a.removeLocked(id, tr, StatusEvicted)
		}
	}
}

func isFinished(st Status) bool {
	return st == StatusClosed || st == StatusClosedGapped ||
		st == StatusReset || st == StatusFailed
}

func (a *Assembler) enforceMaxLocked() {
	if a.cfg.MaxSessions <= 0 || len(a.table) < a.cfg.MaxSessions {
		return
	}
	// Evict the least recently active session, ties broken by flow id.
	var victim FlowID
	var victimTS time.Time
	first := true
	for id, sess := range a.table {
		if first || sess.LastTS.Before(victimTS) ||
			(sess.LastTS.Equal(victimTS) && id.String() < victim.String()) {
			victim, victimTS, first = id, sess.LastTS, false
		}
	}
	a.removeLocked(victim, a.table[victim], StatusEvicted)
}

func (a *Assembler) removeLocked(id FlowID, tr *tracked, st Status) {
	sess := tr.Session
	a.classifyLocked(tr)
	sess.Status = st
	sess.Evicted = true
	delete(a.table, id)
	if a.onEvict != nil {
		a.onEvict(sess)
	}
}

// ActiveCount reports the current table size.
func (a *Assembler) ActiveCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.table)
}
