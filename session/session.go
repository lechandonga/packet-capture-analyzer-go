// Package session reassembles captured packets into per-connection
// sessions. The reassembler is fully offline: it is fed records from
// local pcap files and never touches the network.
//
// Determinism guarantees:
//   - Repeated segments (retransmissions) are counted once: unique byte
//     accounting is based on sequence-number coverage, not packet count.
//   - Overlapping segments are merged with a fixed "first observation
//     wins" rule, so the assembled stream does not depend on whether
//     records arrive in one slice or many small batches.
//   - Missing ranges are tracked as explicit gaps; a session with holes
//     is never reported as a clean close.
//   - Completed/idle sessions are evicted with an order defined only by
//     timestamps and the canonical flow identifier.
package session

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Endpoint identifies one transport endpoint.
type Endpoint struct {
	Addr string
	Port uint16
}

func (e Endpoint) String() string { return fmt.Sprintf("%s:%d", e.Addr, e.Port) }

// FlowID is the direction-independent identity of a TCP/UDP conversation.
type FlowID struct {
	Proto uint8
	A, B  Endpoint // canonical ordering: A <= B
}

func (f FlowID) String() string {
	return fmt.Sprintf("%d %s <-> %s", f.Proto, f.A, f.B)
}

// Status classifies how a conversation ended.
type Status string

const (
	StatusOngoing      Status = "ongoing"
	StatusClosed       Status = "closed"
	StatusClosedGapped Status = "closed_with_gaps"
	StatusReset        Status = "reset"
	StatusFailed       Status = "failed_connect"
	StatusIncomplete   Status = "incomplete"
	StatusEvicted      Status = "evicted"
)

// DirectionStats holds per-direction reassembly counters.
type DirectionStats struct {
	Packets        int64
	DataPackets    int64
	UniqueBytes    int64
	RetransBytes   int64
	OutOfOrderSegs int64
	FINSeen        bool
	RSTSeen        bool
}

// Gap is an unfilled sequence range in one direction (absolute coords).
type Gap struct {
	FromClient bool
	StartSeq   int64
	EndSeq     int64
}

// Session is the reassembled state of one flow.
type Session struct {
	Flow        FlowID
	Client      Endpoint // side that sent the first SYN (UDP: first packet)
	Server      Endpoint
	FirstTS     time.Time
	LastTS      time.Time
	Status      Status
	Packets     int64
	SynSeen     bool
	SynAckSeen  bool
	Established bool
	C2SPayload  []byte
	S2CPayload  []byte
	C2S         DirectionStats
	S2C         DirectionStats
	Gaps        []Gap
	Evicted     bool
	UDP         bool
}

// TotalPayloadBytes returns unique payload bytes in both directions.
func (s *Session) TotalPayloadBytes() int64 {
	return s.C2S.UniqueBytes + s.S2C.UniqueBytes
}

func canon(a, b Endpoint) (Endpoint, Endpoint) {
	if endpointLess(b, a) {
		return b, a
	}
	return a, b
}

func endpointLess(a, b Endpoint) bool {
	if a.Addr != b.Addr {
		return a.Addr < b.Addr
	}
	return a.Port < b.Port
}

type chunk struct {
	start int64
	data  []byte
}

type interval [2]int64

// stream reassembles one TCP direction in absolute coordinates where the
// SYN occupies 0 and the first data byte is 1.
type stream struct {
	hasBase bool
	baseRel uint32
	baseAbs int64

	next    int64
	maxSeen int64

	covered []interval
	pending map[int64]chunk

	out       *[]byte
	maxStored int64
	stats     *DirectionStats

	finAbs int64
	finSet bool
	rst    bool
}

func newStream(out *[]byte, maxStored int64, st *DirectionStats) *stream {
	return &stream{pending: map[int64]chunk{}, out: out, maxStored: maxStored, stats: st}
}

func (s *stream) toAbs(rel uint32) int64 {
	delta := int64(int32(rel - s.baseRel))
	return s.baseAbs + delta
}

func (s *stream) setBase(rel uint32, abs int64) {
	s.hasBase = true
	s.baseRel = rel
	s.baseAbs = abs
	s.next = abs
}

// coverageOverlap counts how many bytes of [lo, hi) are already covered,
// without changing the coverage union.
func (s *stream) coverageOverlap(lo, hi int64) int64 {
	if hi <= lo {
		return 0
	}
	dup := int64(0)
	for _, iv := range s.covered {
		if iv[1] <= lo {
			continue
		}
		if iv[0] >= hi {
			break
		}
		l := lo
		if iv[0] > l {
			l = iv[0]
		}
		h := hi
		if iv[1] < h {
			h = iv[1]
		}
		if h > l {
			dup += h - l
		}
	}
	return dup
}

// addInterval inserts [lo, hi) into the coverage union.
func (s *stream) addInterval(lo, hi int64) {
	if hi <= lo {
		return
	}
	s.covered = insertInterval(s.covered, interval{lo, hi})
}

func insertInterval(ivs []interval, in interval) []interval {
	i := sort.Search(len(ivs), func(i int) bool { return ivs[i][0] > in[0] })
	ivs = append(ivs, interval{})
	copy(ivs[i+1:], ivs[i:])
	ivs[i] = in
	// Merge into the previous interval when overlapping/adjacent.
	if i > 0 && ivs[i-1][1] >= in[0] {
		if ivs[i-1][1] < in[1] {
			ivs[i-1][1] = in[1]
		}
		ivs = append(ivs[:i], ivs[i+1:]...)
		i--
	}
	// Absorb every following interval that overlaps the current one.
	j := i + 1
	for j < len(ivs) && ivs[j][0] <= ivs[i][1] {
		if ivs[j][1] > ivs[i][1] {
			ivs[i][1] = ivs[j][1]
		}
		j++
	}
	if j > i+1 {
		ivs = append(ivs[:i+1], ivs[j:]...)
	}
	return ivs
}

// addPayload feeds one data segment. Empty payloads only count packets.
func (s *stream) addPayload(relSeq uint32, data []byte) {
	s.stats.Packets++
	if len(data) == 0 {
		return
	}
	s.stats.DataPackets++
	if !s.hasBase {
		// Segment without observed SYN: anchor its first byte at 1 so
		// mid-stream captures still have consistent coordinates.
		s.setBase(relSeq, 1)
	}
	start := s.toAbs(relSeq)
	end := start + int64(len(data))
	if end > s.maxSeen {
		s.maxSeen = end
	}
	if start > s.next {
		s.stats.OutOfOrderSegs++
	}
	dup := s.coverageOverlap(start, end)
	if dup > 0 {
		s.stats.RetransBytes += dup
	}
	if dup == int64(len(data)) {
		return
	}
	// Split against coverage BEFORE inserting the new segment so the
	// segment's own bytes are not mistaken for already-covered data.
	pieces := uncoveredPieces(start, data, s.covered)
	s.addInterval(start, end)
	for _, p := range pieces {
		if p.start < s.next {
			continue
		}
		if existing, ok := s.pending[p.start]; ok {
			if len(existing.data) >= len(p.data) {
				continue
			}
		}
		s.pending[p.start] = p
	}
	s.deliver()
}

func uncoveredPieces(start int64, data []byte, covered []interval) []chunk {
	// Intersect the sorted, disjoint coverage union with the segment
	// and emit the set difference, reusing the segment's backing array.
	var out []chunk
	lo, hi := start, start+int64(len(data))
	for _, iv := range covered {
		if iv[1] <= lo {
			continue
		}
		if iv[0] >= hi {
			break
		}
		covLo := iv[0]
		if covLo < lo {
			covLo = lo
		}
		covHi := iv[1]
		if covHi > hi {
			covHi = hi
		}
		if covLo > lo {
			out = append(out, chunk{start: lo, data: data[lo-start : covLo-start]})
		}
		if covHi > lo {
			lo = covHi
		}
	}
	if lo < hi {
		out = append(out, chunk{start: lo, data: data[lo-start : hi-start]})
	}
	return out
}

func (s *stream) deliver() {
	for {
		c, ok := s.pending[s.next]
		if !ok {
			return
		}
		delete(s.pending, s.next)
		if len(c.data) == 0 {
			continue
		}
		if int64(len(*s.out)) < s.maxStored {
			room := s.maxStored - int64(len(*s.out))
			if int64(len(c.data)) <= room {
				*s.out = append(*s.out, c.data...)
			} else {
				*s.out = append(*s.out, c.data[:room]...)
			}
		}
		s.next += int64(len(c.data))
		// baseAbs is the SYN (which consumes one sequence number but
		// carries no data), so delivered data bytes are next-1 when the
		// stream began with a SYN at coordinate 0.
		dataBase := s.baseAbs
		if s.baseAbs == 0 {
			dataBase = 1
		}
		s.stats.UniqueBytes = s.next - dataBase
	}
}

// addSYN registers the synchronize sequence number (occupies seq 0).
func (s *stream) addSYN(relSeq uint32) {
	s.stats.Packets++
	s.setBase(relSeq, 0)
	if s.next < 1 {
		s.next = 1
	}
	s.addInterval(0, 1)
	if s.maxSeen < 1 {
		s.maxSeen = 1
	}
}

func (s *stream) addFIN(relSeq uint32, payloadLen int) {
	if !s.hasBase {
		s.setBase(relSeq, 1)
	}
	edge := s.toAbs(relSeq) + int64(payloadLen)
	s.finSet = true
	s.finAbs = edge
	if edge+1 > s.maxSeen {
		s.maxSeen = edge + 1
	}
	s.addInterval(edge, edge+1)
	s.stats.FINSeen = true
}

func (s *stream) addRST() {
	s.stats.Packets++
	s.rst = true
	s.stats.RSTSeen = true
}

// holes returns unfilled data ranges between the ordered edge and the
// furthest observed byte. The FIN sequence slot is excluded.
func (s *stream) holes() []Gap {
	if !s.hasBase {
		return nil
	}
	var holes []Gap
	cursor := s.next
	for _, iv := range s.covered {
		if iv[1] <= cursor {
			continue
		}
		if iv[0] > cursor {
			holes = append(holes, Gap{StartSeq: cursor, EndSeq: iv[0]})
		}
		cursor = iv[1]
	}
	end := s.maxSeen
	if s.finSet && cursor <= s.finAbs && end == s.finAbs+1 {
		end = s.finAbs // exclude FIN's own sequence slot
	}
	if end > cursor {
		holes = append(holes, Gap{StartSeq: cursor, EndSeq: end})
	}
	return holes
}

func (s *stream) cleanClosed() bool {
	if !s.finSet {
		return false
	}
	return s.next >= s.finAbs && len(s.holes()) == 0
}

// Config controls assembler resource bounds.
type Config struct {
	IdleTimeout            time.Duration
	MaxSessions            int
	MaxPayloadPerDirection int64
	// CompletedRetention bounds how long finished sessions (clean
	// close, reset, failed connect) remain live after their last
	// packet before being reclaimed through the eviction callback. 0
	// uses a 30s default; a negative value keeps them until Flush.
	CompletedRetention time.Duration
}

// DefaultConfig returns conservative bounded defaults.
func DefaultConfig() Config {
	return Config{
		IdleTimeout:            5 * time.Minute,
		MaxSessions:            100000,
		MaxPayloadPerDirection: 1 << 20,
		CompletedRetention:     30 * time.Second,
	}
}

// EvictedHandler receives reclaimed sessions.
type EvictedHandler func(*Session)

// Assembler owns the session table and reassembly lifecycle.
type Assembler struct {
	cfg     Config
	mu      sync.Mutex
	table   map[FlowID]*tracked
	onEvict EvictedHandler
	now     time.Time
}

type tracked struct {
	*Session
	c2s *stream
	s2c *stream
}

// NewAssembler builds an assembler. A nil handler drops evicted sessions.
func NewAssembler(cfg Config, onEvict EvictedHandler) *Assembler {
	if cfg.MaxPayloadPerDirection <= 0 {
		cfg.MaxPayloadPerDirection = 1 << 20
	}
	return &Assembler{cfg: cfg, table: map[FlowID]*tracked{}, onEvict: onEvict}
}
