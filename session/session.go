// Package session reassembles decoded packets into connection-keyed sessions.
// It implements deterministic TCP reassembly (out-of-order queuing,
// duplicate/retransmission detection, overlap trimming and explicit gap
// tracking) and bounds memory by recycling completed and idle sessions.
package session

import (
	"sort"
	"sync"

	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
)

// Status is the observable lifecycle state of a session.
type Status string

const (
	// StatusNew: SYN seen, no response yet.
	StatusNew Status = "new"
	// StatusEstablished: handshake completed.
	StatusEstablished Status = "established"
	// StatusClosed: the connection finished (FIN exchange or RST after data).
	StatusClosed Status = "closed"
	// StatusFailed: the attempt was refused/reset or never got a SYN-ACK.
	StatusFailed Status = "failed"
	// StatusGap: capture ends with unrecovered sequence holes. This is never
	// reported as a normal close.
	StatusGap Status = "gapped"
	// StatusPartial: mid-capture session that never established nor failed.
	StatusPartial Status = "partial"
)

// Direction identifies a side relative to the initiator.
type Direction int

const (
	// DirAtoB / DirBtoA name directions relative to the canonical FlowKey
	// (numeric smaller endpoint A first), which keeps storage independent of
	// the order packets happen to arrive.
	DirAtoB Direction = 0
	DirBtoA Direction = 1
)

// Endpoint is one IP/port pair.
type Endpoint struct {
	IP   []byte
	Port uint16
}

// Stats are per-session counters. Duplicate segments never count twice.
type Stats struct {
	Packets       int
	Retransmits   int
	DuplicateAcks int
	OutOfOrder    int
	OverlapBytes  int
	DataPackets   int
	DataBytes     int
	BytesPerDir   [2]int
}

// Gap describes an unrecovered sequence hole in one direction.
type Gap struct {
	Dir   Direction
	Begin uint32 // first missing sequence number
	End   uint32 // sequence immediately after the hole
	Bytes uint32
}

// Session is one TCP connection (or UDP flow) with its reassembly result.
type Session struct {
	// ID is assigned deterministically in first-seen order.
	ID    int64
	Proto uint8
	Init  Endpoint
	Resp  Endpoint

	Status          Status
	FirstUsec       int64
	LastUsec        int64
	SynSeen         bool
	SynAckSeen      bool
	EstablishedUsec int64
	ClosedUsec      int64
	RSTSeen         bool
	// Attempt is true when the initiator sent a SYN and no SYN-ACK arrived
	// before a RST/end-of-capture (scan/failure evidence).
	Attempt bool
	// initIsA records whether the initiator is endpoint A (true) or B.
	// Before a SYN identifies the initiator it defaults to true.
	initIsA   bool
	initKnown bool

	// PayloadPerDir holds the reassembled application stream, capped per
	// direction by Config.MaxPayloadBytes.
	PayloadPerDir [2][]byte

	// Gaps lists holes still open at close/end.
	Gaps []Gap

	Stats Stats

	packetIndex []int
	recycled    bool
}

// Packets returns captured record indices contributing non-duplicate
// segments, in arrival order.
func (s *Session) Packets() []int {
	out := make([]int, len(s.packetIndex))
	copy(out, s.packetIndex)
	return out
}

// DurationUsec returns the observed session duration.
func (s *Session) DurationUsec() int64 {
	if s.LastUsec < s.FirstUsec {
		return 0
	}
	return s.LastUsec - s.FirstUsec
}

// FlowKey canonically identifies a connection independent of packet
// direction; the smaller endpoint sorts first.
type FlowKey struct {
	Proto  uint8
	AIP    [16]byte
	APort  uint16
	AIPLen int
	BIP    [16]byte
	BPort  uint16
	BIPLen int
}

// Config controls the Engine.
type Config struct {
	// MaxActive hard-caps simultaneously retained live sessions.
	MaxActive int
	// IdleTimeoutUsec: sessions idle for at least this long (on the packet
	// clock) are finalised and recycled.
	IdleTimeoutUsec int64
	// MaxPendingSegments bounds queued out-of-order segments per direction.
	MaxPendingSegments int
	// MaxPayloadBytes caps retained reassembled payload per direction.
	MaxPayloadBytes int
	// MaxEvidencePerSession caps recorded packet indices.
	MaxEvidencePerSession int
}

// DefaultConfig returns conservative, purely defensive bounds.
func DefaultConfig() Config {
	return Config{
		MaxActive:             100_000,
		IdleTimeoutUsec:       120_000_000,
		MaxPendingSegments:    10_000,
		MaxPayloadBytes:       1 << 20,
		MaxEvidencePerSession: 256,
	}
}

// Engine reassembles packets into sessions.
type Engine struct {
	cfg Config
	mu  sync.Mutex

	sessions map[FlowKey]*Session
	streams  map[FlowKey]*[2]*stream
	nextID   int64

	recycled    []*Session
	maxRecycled int

	lastClock int64

	// RejectedPending counts drops caused by the pending-segment bound.
	RejectedPending int
}

// NewEngine builds an Engine; zero fields are replaced by defaults.
func NewEngine(cfg Config) *Engine {
	d := DefaultConfig()
	if cfg.MaxActive <= 0 {
		cfg.MaxActive = d.MaxActive
	}
	if cfg.IdleTimeoutUsec <= 0 {
		cfg.IdleTimeoutUsec = d.IdleTimeoutUsec
	}
	if cfg.MaxPendingSegments <= 0 {
		cfg.MaxPendingSegments = d.MaxPendingSegments
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = d.MaxPayloadBytes
	}
	if cfg.MaxEvidencePerSession <= 0 {
		cfg.MaxEvidencePerSession = d.MaxEvidencePerSession
	}
	return &Engine{
		cfg:         cfg,
		sessions:    map[FlowKey]*Session{},
		streams:     map[FlowKey]*[2]*stream{},
		maxRecycled: cfg.MaxActive,
	}
}

// HandlePacket feeds one decoded packet and returns its session (the same
// pointer for every packet of the connection), or nil when the packet carries
// neither TCP nor UDP.
func (e *Engine) HandlePacket(p *pcap.Packet) *Session {
	e.mu.Lock()
	defer e.mu.Unlock()

	if p.TCP == nil && p.UDP == nil {
		return nil
	}
	ts := p.Sec*1_000_000 + p.Usec
	if ts > e.lastClock {
		e.lastClock = ts
	}
	key, c2s := canonicalKey(p)
	sess := e.sessions[key]
	if sess == nil {
		sess = e.newSession(p, key, ts)
		e.sessions[key] = sess
		e.streams[key] = &[2]*stream{newStream(), newStream()}
		e.gcLocked(ts)
	}
	if sess.FirstUsec == 0 || ts < sess.FirstUsec {
		sess.FirstUsec = ts
	}
	if ts > sess.LastUsec {
		sess.LastUsec = ts
	}
	if p.TCP != nil {
		dir := DirBtoA
		if c2s {
			dir = DirAtoB
		}
		e.handleTCP(sess, key, e.streams[key][dir], dir, p, ts)
	} else {
		dir := DirBtoA
		if c2s {
			dir = DirAtoB
		}
		e.handleUDP(sess, p, dir)
	}
	e.recordIndex(sess, p.Index)
	return sess
}

func (e *Engine) recordIndex(sess *Session, idx int) {
	if len(sess.packetIndex) < e.cfg.MaxEvidencePerSession {
		sess.packetIndex = append(sess.packetIndex, idx)
		return
	}
	h := e.cfg.MaxEvidencePerSession / 2
	copy(sess.packetIndex[h:], sess.packetIndex[h+1:])
	sess.packetIndex[e.cfg.MaxEvidencePerSession-1] = idx
}

func (e *Engine) newSession(p *pcap.Packet, key FlowKey, ts int64) *Session {
	e.nextID++
	s := &Session{ID: e.nextID, FirstUsec: ts, LastUsec: ts, Status: StatusPartial}
	if p.TCP != nil {
		s.Proto = 6
	} else {
		s.Proto = 17
	}
	s.Init = Endpoint{IP: append([]byte(nil), key.AIP[:key.AIPLen]...), Port: key.APort}
	s.Resp = Endpoint{IP: append([]byte(nil), key.BIP[:key.BIPLen]...), Port: key.BPort}
	s.initIsA = true
	if p.TCP != nil && p.TCP.Flags&pcap.TCPSyn != 0 && p.TCP.Flags&pcap.TCPAck == 0 {
		s.Status = StatusNew
		s.SynSeen = true
		s.Attempt = true
		s.initKnown = true
	}
	return s
}

func (e *Engine) handleUDP(sess *Session, p *pcap.Packet, dir Direction) {
	n := len(p.Payload)
	sess.Stats.Packets++
	if n > 0 {
		sess.Stats.DataPackets++
		sess.Stats.DataBytes += n
		sess.Stats.BytesPerDir[dir] += n
		e.appendPayload(sess, dir, p.Payload)
	}
	if sess.Status == StatusPartial || sess.Status == StatusNew {
		sess.Status = StatusEstablished
	}
}

// Flush finalises every open session at the packet clock (missing data becomes
// explicit gaps; unfinished attempts become failures) and returns all known
// sessions in deterministic ID order.
func (e *Engine) Flush() []*Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, sess := range e.sessions {
		e.finalizeSessionLocked(key, sess)
	}
	out := make([]*Session, 0, len(e.sessions)+len(e.recycled))
	for _, s := range e.sessions {
		out = append(out, s)
	}
	out = append(out, e.recycled...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ActiveSessions returns live sessions in deterministic ID order.
func (e *Engine) ActiveSessions() []*Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Session, 0, len(e.sessions))
	for _, s := range e.sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// RecycledSessions returns evicted session summaries in eviction order.
func (e *Engine) RecycledSessions() []*Session {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*Session, len(e.recycled))
	copy(out, e.recycled)
	return out
}

// ReapIdle reclaims sessions idle since nowUsec; finalises stale open ones.
func (e *Engine) ReapIdle(nowUsec int64) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if nowUsec > e.lastClock {
		e.lastClock = nowUsec
	}
	return e.gcLocked(nowUsec)
}

func (e *Engine) finalizeSessionLocked(key FlowKey, sess *Session) {
	if sess.recycled {
		return
	}
	if sess.Proto == 6 {
		if ss, ok := e.streams[key]; ok {
			for dir := DirAtoB; dir <= DirBtoA; dir++ {
				for _, g := range ss[dir].openGaps() {
					g.Dir = dir
					sess.Gaps = append(sess.Gaps, g)
				}
			}
		}
	}
	switch {
	case sess.Status == StatusClosed:
		// keep
	case sess.Attempt && !sess.SynAckSeen:
		sess.Status = StatusFailed
	case sess.Proto == 6 && len(sess.Gaps) > 0:
		sess.Status = StatusGap
	case sess.Status == StatusNew:
		sess.Status = StatusFailed
	default:
		// partial / established without FIN: keep as-is
		if sess.Proto == 17 && sess.Status == StatusPartial {
			// UDP flows with no payload stay partial
		}
	}
}

func (e *Engine) gcLocked(now int64) int {
	type cand struct {
		key FlowKey
		s   *Session
	}
	var dead []cand
	for key, s := range e.sessions {
		if now-s.LastUsec >= e.cfg.IdleTimeoutUsec {
			dead = append(dead, cand{key, s})
		}
	}
	sort.Slice(dead, func(i, j int) bool {
		if dead[i].s.LastUsec != dead[j].s.LastUsec {
			return dead[i].s.LastUsec < dead[j].s.LastUsec
		}
		return dead[i].s.ID < dead[j].s.ID
	})
	reaped := len(dead)
	for _, c := range dead {
		e.finalizeSessionLocked(c.key, c.s)
		e.recycleLocked(c.key, c.s)
	}
	if len(e.sessions) > e.cfg.MaxActive {
		all := make([]cand, 0, len(e.sessions))
		for key, s := range e.sessions {
			all = append(all, cand{key, s})
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].s.LastUsec != all[j].s.LastUsec {
				return all[i].s.LastUsec < all[j].s.LastUsec
			}
			return all[i].s.ID < all[j].s.ID
		})
		excess := len(all) - e.cfg.MaxActive
		for _, c := range all[:excess] {
			e.finalizeSessionLocked(c.key, c.s)
			e.recycleLocked(c.key, c.s)
			reaped++
		}
	}
	return reaped
}

func (e *Engine) recycleLocked(key FlowKey, s *Session) {
	s.recycled = true
	delete(e.sessions, key)
	delete(e.streams, key)
	// drop large payloads, keep gaps/stats/endpoints for evidence
	s.PayloadPerDir = [2][]byte{nil, nil}
	e.recycled = append(e.recycled, s)
	if len(e.recycled) > e.maxRecycled {
		e.recycled = e.recycled[len(e.recycled)-e.maxRecycled:]
	}
}
