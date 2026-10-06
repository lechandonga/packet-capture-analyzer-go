package session

import (
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
)

func (e *Engine) appendPayload(sess *Session, dir Direction, data []byte) {
	room := e.cfg.MaxPayloadBytes - len(sess.PayloadPerDir[dir])
	if room <= 0 {
		return
	}
	if len(data) > room {
		data = data[:room]
	}
	sess.PayloadPerDir[dir] = append(sess.PayloadPerDir[dir], data...)
}

// initiatorDir returns the canonical Direction carrying initiator traffic.
func (s *Session) initiatorDir() Direction {
	if s.initIsA {
		return DirAtoB
	}
	return DirBtoA
}

func (e *Engine) handleTCP(sess *Session, key FlowKey, st *stream, dir Direction, p *pcap.Packet, ts int64) {
	t := p.TCP
	res := st.ingest(t, p.Payload, p.Index)

	isBareSyn := t.Flags&pcap.TCPSyn != 0 && t.Flags&pcap.TCPAck == 0
	isSynAck := t.Flags&pcap.TCPSyn != 0 && t.Flags&pcap.TCPAck != 0
	if isBareSyn {
		sess.SynSeen = true
		sess.Attempt = true
		if !sess.initKnown {
			sess.initKnown = true
			sess.initIsA = dir == DirAtoB
			if dir == DirAtoB {
				sess.Init = Endpoint{IP: append([]byte(nil), key.AIP[:key.AIPLen]...), Port: key.APort}
				sess.Resp = Endpoint{IP: append([]byte(nil), key.BIP[:key.BIPLen]...), Port: key.BPort}
			} else {
				sess.Init = Endpoint{IP: append([]byte(nil), key.BIP[:key.BIPLen]...), Port: key.BPort}
				sess.Resp = Endpoint{IP: append([]byte(nil), key.AIP[:key.AIPLen]...), Port: key.APort}
			}
		}
		if sess.Status == StatusPartial {
			sess.Status = StatusNew
		}
	} else if isSynAck {
		// SYN-ACK must travel responder -> initiator.
		if sess.initKnown && dir != sess.initiatorDir() {
			sess.SynAckSeen = true
		} else if !sess.initKnown {
			// Infer initiator from a lone SYN-ACK (capture starts mid-shake).
			sess.initKnown = true
			sess.initIsA = dir != DirAtoB
			sess.SynAckSeen = true
		}
	}
	if sess.SynSeen && sess.SynAckSeen && sess.Status == StatusNew {
		if t.Flags&pcap.TCPAck != 0 && dir == sess.initiatorDir() {
			sess.Status = StatusEstablished
			sess.EstablishedUsec = ts
		}
	}

	if res.isDupAck {
		sess.Stats.Packets++
		sess.Stats.DuplicateAcks++
		return
	}
	sess.Stats.Packets++
	if res.isRetransmit {
		sess.Stats.Retransmits++
		return
	}
	if res.outOfOrder {
		sess.Stats.OutOfOrder++
	}
	if res.overlapBytes > 0 {
		sess.Stats.OverlapBytes += res.overlapBytes
	}
	if len(res.appended) > 0 {
		sess.Stats.DataPackets++
		sess.Stats.DataBytes += len(res.appended)
		sess.Stats.BytesPerDir[dir] += len(res.appended)
		e.appendPayload(sess, dir, res.appended)
	}

	if t.Flags&pcap.TCPRst != 0 {
		sess.RSTSeen = true
		if sess.Attempt && !sess.SynAckSeen {
			sess.Status = StatusFailed
		} else if sess.Status != StatusFailed {
			sess.Status = StatusClosed
			sess.ClosedUsec = ts
		}
		return
	}

	ss := e.streams[key]
	if ss[DirAtoB].closed() && ss[DirBtoA].closed() {
		if sess.Status != StatusFailed {
			sess.Status = StatusClosed
			sess.ClosedUsec = ts
		}
	}
}
