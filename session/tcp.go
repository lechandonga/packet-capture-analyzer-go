package session

import (
	"bytes"
	"sort"

	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
)

// seg is one received TCP segment relevant to reassembly.
type seg struct {
	seq    uint32
	data   []byte
	flags  uint8
	pktIdx int
}

// stream reassembles one direction of a TCP connection.
type stream struct {
	init   bool
	base   uint32 // next expected sequence number (ISN+1 after SYN)
	finSeq uint32 // sequence of FIN, set once
	sawFin bool
	sawRST bool

	received bytes.Buffer // contiguous data delivered from base onward
	pending  []seg        // out-of-order segments beyond base
	seen     map[uint32]bool

	dupAckLast uint32
	dupAckRun  int
}

func newStream() *stream { return &stream{seen: map[uint32]bool{}} }

// ingest processes one segment. It returns a result describing how the
// segment was classified so the engine can update counters deterministically.
type ingestResult struct {
	accepted     bool // non-duplicate data bytes appended (immediately or later)
	isRetransmit bool
	isDupAck     bool
	outOfOrder   bool
	overlapBytes int
	appended     []byte // data newly made contiguous
}

func (s *stream) ingest(t *pcap.TCPHeader, payload []byte, pktIdx int) ingestResult {
	var res ingestResult
	if t.Flags&pcap.TCPRst != 0 {
		s.sawRST = true
	}
	if t.Flags&pcap.TCPSyn != 0 {
		if !s.init {
			s.init = true
			s.base = t.Seq + 1 // SYN consumes one sequence number
			s.seen = map[uint32]bool{}
		}
	}
	// Pure ACK duplicate detection (no data, no SYN/FIN).
	noData := len(payload) == 0 && t.Flags&(pcap.TCPSyn|pcap.TCPFin|pcap.TCPRst) == 0
	if noData {
		if s.dupAckRun > 0 && t.Ack == s.dupAckLast {
			s.dupAckRun++
			res.isDupAck = true
			return res
		}
		s.dupAckLast = t.Ack
		s.dupAckRun = 1
		return res
	}

	if !s.init {
		// Mid-capture: anchor on the first data-bearing segment's sequence.
		s.init = true
		s.base = t.Seq
		s.seen = map[uint32]bool{}
	}

	dataSeq := t.Seq
	if t.Flags&pcap.TCPSyn != 0 {
		dataSeq = t.Seq + 1
	}

	// FIN bookkeeping.
	if t.Flags&pcap.TCPFin != 0 {
		fin := dataSeq + uint32(len(payload))
		if !s.sawFin || seqLT(fin, s.finSeq) {
			s.finSeq = fin
		}
		s.sawFin = true
	}

	if len(payload) == 0 {
		return res
	}

	// Duplicate: an identical (seq,length) already fully accounted for.
	key := dataSeq
	end := dataSeq + uint32(len(payload))
	if s.seen[key] && !seqLT(s.base, end) {
		res.isRetransmit = true
		return res
	}

	relBegin := int(seqSub(dataSeq, s.base))
	switch {
	case relBegin < 0:
		// Overlaps already-received region; trim or classify retransmit.
		if !seqLT(end, s.base) {
			trimmed := payload[-relBegin:]
			if len(trimmed) > 0 {
				res2 := s.ingest(&pcap.TCPHeader{Seq: s.base, Ack: t.Ack, Flags: t.Flags &^ pcap.TCPSyn}, trimmed, pktIdx)
				res2.overlapBytes += -relBegin
				return res2
			}
		}
		res.isRetransmit = true
		return res
	case relBegin == s.received.Len():
		// In-order segment.
		appended := s.deliver(payload)
		appended = append(appended, s.drainPending()...)
		res.appended = appended
		res.accepted = len(appended) > 0
		if len(appended) < len(payload) {
			res.overlapBytes += len(payload) - len(appended)
		}
	case relBegin > s.received.Len():
		// Future segment: queue if genuinely new.
		if s.seen[key] {
			res.isRetransmit = true
			return res
		}
		s.pending = append(s.pending, seg{seq: dataSeq, data: append([]byte(nil), payload...), flags: t.Flags, pktIdx: pktIdx})
		sort.SliceStable(s.pending, func(i, j int) bool { return seqLT(s.pending[i].seq, s.pending[j].seq) })
		res.outOfOrder = true
		res.accepted = true
	default:
		// Fills part of a gap but overlaps contiguous tail region: trim head.
		off := s.received.Len() - relBegin
		if off < len(payload) {
			appended := s.deliver(payload[off:])
			appended = append(appended, s.drainPending()...)
			res.appended = appended
			res.accepted = len(appended) > 0
			res.overlapBytes += off
		} else {
			res.isRetransmit = true
		}
	}
	if res.isRetransmit {
		return res
	}
	s.seen[key] = true
	return res
}

func (s *stream) deliver(data []byte) []byte {
	want := s.received.Len()
	n := len(data)
	if n == 0 {
		return nil
	}
	s.received.Write(data)
	return s.received.Bytes()[want:]
}

// drainPending appends all segments that have become contiguous and returns
// the newly delivered bytes (so the engine can mirror them into the session
// payload exactly once).
func (s *stream) drainPending() []byte {
	var delivered []byte
	for len(s.pending) > 0 {
		head := s.pending[0]
		rel := int(seqSub(head.seq, s.base))
		if rel > s.received.Len() {
			return delivered
		}
		s.pending = s.pending[1:]
		if rel < s.received.Len() {
			off := s.received.Len() - rel
			if off < len(head.data) {
				delivered = append(delivered, s.deliver(head.data[off:])...)
			}
			continue
		}
		delivered = append(delivered, s.deliver(head.data)...)
	}
	return delivered
}

// openGaps returns holes between the contiguous stream and segments queued or
// the FIN position.
func (s *stream) openGaps() []Gap {
	if !s.init {
		return nil
	}
	var gaps []Gap
	contigEnd := s.base + uint32(s.received.Len())
	cursor := contigEnd
	var farEnd uint32
	haveFar := false
	for _, p := range s.pending {
		pEnd := p.seq + uint32(len(p.data))
		if !haveFar || seqLT(farEnd, pEnd) {
			farEnd, haveFar = pEnd, true
		}
	}
	if s.sawFin && (!haveFar || seqLT(farEnd, s.finSeq)) {
		farEnd, haveFar = s.finSeq, true
	}
	if !haveFar || !seqLT(cursor, farEnd) {
		return nil
	}
	// Walk queued segments in order and emit holes.
	pending := append([]seg(nil), s.pending...)
	sort.Slice(pending, func(i, j int) bool { return seqLT(pending[i].seq, pending[j].seq) })
	for _, p := range pending {
		if seqLT(p.seq, cursor) {
			continue
		}
		if seqLT(cursor, p.seq) {
			gaps = append(gaps, Gap{Begin: cursor, End: p.seq, Bytes: seqSub(p.seq, cursor)})
		}
		end := p.seq + uint32(len(p.data))
		if seqLT(cursor, end) {
			cursor = end
		}
	}
	if seqLT(cursor, farEnd) {
		gaps = append(gaps, Gap{Begin: cursor, End: farEnd, Bytes: seqSub(farEnd, cursor)})
	}
	return gaps
}

// closed reports whether this direction has consumed its FIN (all bytes up to
// finSeq are contiguous) or was terminated by RST.
func (s *stream) closed() bool {
	if s.sawRST {
		return true
	}
	if !s.sawFin {
		return false
	}
	return s.base+uint32(s.received.Len()) == s.finSeq && len(s.pending) == 0
}

// seq arithmetic with 32-bit wrap (RFC 1982 style, distance < 2^31).
func seqLT(a, b uint32) bool    { return int32(a-b) < 0 }
func seqSub(a, b uint32) uint32 { return a - b }
