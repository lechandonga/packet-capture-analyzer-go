package session_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/internal/pcapgen"
	"github.com/lechandonga/packet-capture-analyzer-go/internal/testutil"
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

func feed(t *testing.T, eng *session.Engine, b *pcapgen.Builder) []*pcap.Packet {
	t.Helper()
	data := b.Bytes()
	r, err := pcap.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	var fed []*pcap.Packet
	for {
		p, e := r.Read()
		if e != nil {
			break
		}
		eng.HandlePacket(p)
		fed = append(fed, p)
	}
	return fed
}

var (
	m1 = [6]byte{0, 0, 0, 0, 0, 1}
	m2 = [6]byte{0, 0, 0, 0, 0, 2}
	c  = [4]byte{192, 0, 2, 10}
	s  = [4]byte{203, 0, 113, 5}
)

func seg(sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return pcapgen.EthIP4TCP(m1, m2, c, s, sport, dport, seq, ack, flags, payload)
}
func segRev(sport, dport uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	return pcapgen.EthIP4TCP(m2, m1, s, c, sport, dport, seq, ack, flags, payload)
}

func TestOutOfOrderRetransmitOverlap(t *testing.T) {
	testutil.DomainBanner(t, "tcp-reassembly")

	t.Run("out-of-order delivery reassembles in sequence order", func(t *testing.T) {
		cs := testutil.Start(t, "tcp-reassembly", "out-of-order")
		b := pcapgen.New()
		const isnC, isnS = 1000, 5000
		b.Add(seg(40000, 443, isnC, 0, pcap.TCPSyn, nil))
		b.Add(segRev(443, 40000, isnS, isnC+1, pcap.TCPSyn|pcap.TCPAck, nil))
		b.Add(seg(40000, 443, isnC+1, isnS+1, pcap.TCPAck, nil))
		// data arrives as chunk B, chunk A, chunk C
		chunkA := []byte("AAAA")
		chunkB := []byte("BBBB")
		chunkC := []byte("CCCC")
		b.Add(seg(40000, 443, isnC+5, isnS+1, pcap.TCPAck|pcap.TCPPsh, chunkB))
		b.Add(seg(40000, 443, isnC+1, isnS+1, pcap.TCPAck|pcap.TCPPsh, chunkA))
		b.Add(seg(40000, 443, isnC+9, isnS+1, pcap.TCPAck|pcap.TCPPsh, chunkC))
		b.Add(seg(40000, 443, isnC+13, isnS+1, pcap.TCPAck|pcap.TCPFin, nil))
		b.Add(segRev(443, 40000, isnS+1, isnC+14, pcap.TCPAck, nil))
		b.Add(segRev(443, 40000, isnS+1, isnC+14, pcap.TCPAck|pcap.TCPFin, nil))
		b.Add(seg(40000, 443, isnC+14, isnS+2, pcap.TCPAck, nil))

		eng := session.NewEngine(session.Config{})
		feed(t, eng, b)
		sessions := eng.Flush()
		if len(sessions) != 1 {
			cs.Fail("want 1 session, got %d", len(sessions))
			return
		}
		sess := sessions[0]
		want := "AAAABBBBCCCC"
		var dirPayload []byte
		// initiator is 192.0.2.10 (smaller IP than 203.0.113.5) => A side
		dirPayload = sess.PayloadPerDir[session.DirAtoB]
		if string(dirPayload) != want {
			cs.Fail("payload=%q want %q; stats=%+v", dirPayload, want, sess.Stats)
			return
		}
		if sess.Stats.OutOfOrder < 1 {
			cs.Fail("expected out-of-order count >=1, got %d", sess.Stats.OutOfOrder)
			return
		}
		if sess.Status != session.StatusClosed {
			cs.Fail("status=%s want closed; gaps=%v", sess.Status, sess.Gaps)
			return
		}
		cs.Pass("reassembled %q out-of-order=%d status=%s", dirPayload, sess.Stats.OutOfOrder, sess.Status)
	})

	t.Run("retransmitted identical segments counted once", func(t *testing.T) {
		cs := testutil.Start(t, "tcp-reassembly", "retransmit-dedupe")
		b := pcapgen.New()
		const isnC, isnS = 2000, 7000
		b.Add(seg(40001, 443, isnC, 0, pcap.TCPSyn, nil))
		b.Add(segRev(443, 40001, isnS, isnC+1, pcap.TCPSyn|pcap.TCPAck, nil))
		b.Add(seg(40001, 443, isnC+1, isnS+1, pcap.TCPAck, nil))
		payload := []byte("DATA")
		for i := 0; i < 3; i++ {
			b.AddAt(uint32(10000+i*100), seg(40001, 443, isnC+1, isnS+1, pcap.TCPAck|pcap.TCPPsh, payload))
		}
		b.Add(seg(40001, 443, isnC+5, isnS+1, pcap.TCPAck|pcap.TCPFin, nil))
		b.Add(segRev(443, 40001, isnS+1, isnC+6, pcap.TCPAck|pcap.TCPFin, nil))
		b.Add(seg(40001, 443, isnC+6, isnS+2, pcap.TCPAck, nil))
		eng := session.NewEngine(session.Config{})
		feed(t, eng, b)
		sessions := eng.Flush()
		sess := sessions[0]
		if string(sess.PayloadPerDir[session.DirAtoB]) != "DATA" {
			cs.Fail("payload=%q", sess.PayloadPerDir[session.DirAtoB])
			return
		}
		if sess.Stats.Retransmits != 2 || sess.Stats.DataBytes != 4 {
			cs.Fail("retransmits=%d dataBytes=%d stats=%+v", sess.Stats.Retransmits, sess.Stats.DataBytes, sess.Stats)
			return
		}
		cs.Pass("payload once, retransmits=%d bytes=%d", sess.Stats.Retransmits, sess.Stats.DataBytes)
	})

	t.Run("overlapping segments are trimmed and gap reported on hole", func(t *testing.T) {
		cs := testutil.Start(t, "tcp-reassembly", "overlap-and-gap")
		b := pcapgen.New()
		const isnC, isnS = 3000, 9000
		b.Add(seg(40002, 443, isnC, 0, pcap.TCPSyn, nil))
		b.Add(segRev(443, 40002, isnS, isnC+1, pcap.TCPSyn|pcap.TCPAck, nil))
		b.Add(seg(40002, 443, isnC+1, isnS+1, pcap.TCPAck, nil))
		// A..H with bytes 5..8 missing (D-G), overlap: resend 1..4 as XXXX
		b.Add(seg(40002, 443, isnC+1, isnS+1, pcap.TCPAck|pcap.TCPPsh, []byte("ABCD")))
		b.Add(seg(40002, 443, isnC+9, isnS+1, pcap.TCPAck|pcap.TCPPsh, []byte("HIJK")))
		b.Add(seg(40002, 443, isnC+1, isnS+1, pcap.TCPAck|pcap.TCPPsh, []byte("ABCD"))) // duplicate
		// finish from both sides: gap remains because D-G never arrives
		b.Add(seg(40002, 443, isnC+13, isnS+1, pcap.TCPAck|pcap.TCPFin, nil))
		b.Add(segRev(443, 40002, isnS+1, isnC+14, pcap.TCPAck|pcap.TCPFin, nil))
		eng := session.NewEngine(session.Config{})
		feed(t, eng, b)
		sessions := eng.Flush()
		sess := sessions[0]
		if sess.Status != session.StatusGap {
			cs.Fail("status=%s want gapped", sess.Status)
			return
		}
		if len(sess.Gaps) == 0 {
			cs.Fail("expected explicit gap, got none; payload=%q", sess.PayloadPerDir[session.DirAtoB])
			return
		}
		if sess.Stats.Retransmits != 1 {
			cs.Fail("want 1 retransmit, got %d", sess.Stats.Retransmits)
			return
		}
		cs.Pass("status=%s gaps=%+v retransmits=%d", sess.Status, sess.Gaps, sess.Stats.Retransmits)
	})
}

func TestSessionReclaim(t *testing.T) {
	testutil.DomainBanner(t, "session-lifecycle")

	t.Run("idle sessions are finalized and recycled under load", func(t *testing.T) {
		cs := testutil.Start(t, "session-lifecycle", "idle-reclaim")
		eng := session.NewEngine(session.Config{MaxActive: 5, IdleTimeoutUsec: int64(10 * time.Second / time.Microsecond)})
		// 20 short failed SYNs spaced 1 second apart; early ones must be reaped.
		for i := 0; i < 20; i++ {
			b := pcapgen.New()
			src := [4]byte{10, byte(i >> 8), byte(i), 1}
			dst := [4]byte{10, 1, 1, 1}
			frame := pcapgen.EthIP4TCP(m1, m2, src, dst, 40000, 80, 1, 0, pcap.TCPSyn, nil)
			b.AddAt(uint32(i)*1_000_000, frame)
			r, _ := pcap.NewReader(bytes.NewReader(b.Bytes()))
			p, _ := r.Read()
			eng.HandlePacket(p)
		}
		active := eng.ActiveSessions()
		recycled := eng.RecycledSessions()
		if len(active) > 5 {
			cs.Fail("active=%d exceeds cap 5", len(active))
			return
		}
		if len(recycled) == 0 {
			cs.Fail("expected recycled sessions, got 0")
			return
		}
		for _, sess := range recycled {
			if sess.Status != session.StatusFailed {
				cs.Fail("recycled session #%d status=%s, want failed", sess.ID, sess.Status)
				return
			}
		}
		cs.Pass("active=%d recycled=%d all finalized failed", len(active), len(recycled))
	})
}
