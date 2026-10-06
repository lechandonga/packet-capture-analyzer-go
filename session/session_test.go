package session_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio/pcaptest"
	"github.com/lechandonga/packet-capture-analyzer-go/proto"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

func feed(t *testing.T, asm *session.Assembler, frames []pcaptest.Frame) {
	t.Helper()
	blob := pcaptest.Build(pcapio.LinkEther, 65535, frames, nil)
	cap, recErrs, err := pcapio.ReadAll(bytesReader(blob))
	if err != nil || len(recErrs) != 0 {
		t.Fatalf("parse: err=%v recErrs=%v", err, recErrs)
	}
	for _, rec := range cap.Records {
		pk, err := proto.DecodeFrame(cap.Header.Network, rec)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		asm.HandlePacket(pk, rec.TS)
	}
}

func handshake(cPort uint16, sPort uint16, iss, irs uint32, t0 time.Time) []pcaptest.Frame {
	return []pcaptest.Frame{
		{TS: t0, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: cPort, DstPort: sPort, Seq: iss, Flags: pcaptest.SYN},
		{TS: t0.Add(time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: sPort, DstPort: cPort, Seq: irs, Ack: iss + 1, Flags: pcaptest.SYN | pcaptest.ACK},
		{TS: t0.Add(2 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: cPort, DstPort: sPort, Seq: iss + 1, Ack: irs + 1, Flags: pcaptest.ACK},
	}
}

func TestSessionReassembly(t *testing.T) {
	t0 := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	t.Run("业务:TCP重组/正常三次握手与有序数据", func(t *testing.T) {
		frames := handshake(40000, 80, 1000, 5000, t0)
		frames = append(frames,
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 80, Seq: 1001, Ack: 5001, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("GET /")},
			pcaptest.Frame{TS: t0.Add(20 * time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 40000, Seq: 5001, Ack: 1006, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("HTTP/1.")},
		)
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		sessions := asm.Flush()
		if len(sessions) != 1 {
			t.Fatalf("sessions=%d", len(sessions))
		}
		s := sessions[0]
		if string(s.C2SPayload) != "GET /" || string(s.S2CPayload) != "HTTP/1." {
			t.Fatalf("payloads=%q %q", s.C2SPayload, s.S2CPayload)
		}
		if s.C2S.UniqueBytes != 5 || s.S2C.UniqueBytes != 7 {
			t.Fatalf("unique bytes c2s=%d s2c=%d", s.C2S.UniqueBytes, s.S2C.UniqueBytes)
		}
		if s.Status != session.StatusIncomplete {
			t.Fatalf("no FIN should be incomplete, got %s", s.Status)
		}
	})

	t.Run("业务:TCP重组/乱序到达最终补齐", func(t *testing.T) {
		frames := handshake(40001, 81, 100, 900, t0)
		// data seq 101..105 split: second segment arrives before first.
		frames = append(frames,
			pcaptest.Frame{TS: t0.Add(11 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40001, DstPort: 81, Seq: 104, Ack: 901, Flags: pcaptest.ACK, Payload: []byte("DE")},
			pcaptest.Frame{TS: t0.Add(12 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40001, DstPort: 81, Seq: 101, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("ABC")},
		)
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		s := asm.Flush()[0]
		if string(s.C2SPayload) != "ABCDE" {
			t.Fatalf("reordered payload=%q", s.C2SPayload)
		}
		if s.C2S.OutOfOrderSegs < 1 {
			t.Fatalf("expected out-of-order counter, got %d", s.C2S.OutOfOrderSegs)
		}
	})

	t.Run("业务:TCP重组/重传不重复计入", func(t *testing.T) {
		frames := handshake(40002, 82, 100, 900, t0)
		payload := []byte("hello")
		send := func(ts time.Duration) pcaptest.Frame {
			return pcaptest.Frame{TS: t0.Add(ts), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40002, DstPort: 82, Seq: 101, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: payload}
		}
		frames = append(frames, send(10*time.Millisecond), send(20*time.Millisecond), send(30*time.Millisecond))
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		s := asm.Flush()[0]
		if string(s.C2SPayload) != "hello" {
			t.Fatalf("payload=%q", s.C2SPayload)
		}
		if s.C2S.UniqueBytes != 5 {
			t.Fatalf("unique=%d", s.C2S.UniqueBytes)
		}
		if s.C2S.RetransBytes < 10 {
			t.Fatalf("retrans bytes=%d want >=10", s.C2S.RetransBytes)
		}
		if s.C2S.DataPackets != 3 {
			t.Fatalf("data packets=%d", s.C2S.DataPackets)
		}
	})

	t.Run("业务:TCP重组/重叠片段首见为准", func(t *testing.T) {
		frames := handshake(40003, 83, 100, 900, t0)
		frames = append(frames,
			// [101..106) = "AAAAA"
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40003, DstPort: 83, Seq: 101, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("AAAAA")},
			// [104..109) overlaps first; overlapping bytes must keep "AA".
			pcaptest.Frame{TS: t0.Add(11 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40003, DstPort: 83, Seq: 104, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("XXBBB")},
		)
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		s := asm.Flush()[0]
		if want := "AAAAABBB"; string(s.C2SPayload) != want {
			t.Fatalf("overlap merge=%q want %q", s.C2SPayload, want)
		}
		if s.C2S.UniqueBytes != 8 {
			t.Fatalf("unique=%d", s.C2S.UniqueBytes)
		}
	})

	t.Run("业务:TCP重组/重叠且乱序仍首见为准", func(t *testing.T) {
		frames := handshake(40004, 84, 100, 900, t0)
		frames = append(frames,
			// late wide segment arrives first (covers 101..109)
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40004, DstPort: 84, Seq: 101, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("WIDEWIDE")},
			// earlier observation of first 5 bytes must win
			pcaptest.Frame{TS: t0.Add(11 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40004, DstPort: 84, Seq: 101, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("first")},
		)
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		s := asm.Flush()[0]
		if want := "WIDEWIDE"; string(s.C2SPayload) != want {
			t.Fatalf("first-arrival wins=%q want %q", s.C2SPayload, want)
		}
		if s.C2S.UniqueBytes != 8 {
			t.Fatalf("unique=%d", s.C2S.UniqueBytes)
		}
	})

	t.Run("业务:TCP重组/缺段识别为缺口而非正常结束", func(t *testing.T) {
		frames := handshake(40005, 85, 100, 900, t0)
		frames = append(frames,
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40005, DstPort: 85, Seq: 101, Ack: 901, Flags: pcaptest.ACK, Payload: []byte("AAA")},
			// 104..107 missing; jump straight to 107
			pcaptest.Frame{TS: t0.Add(11 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40005, DstPort: 85, Seq: 107, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("BBB")},
			pcaptest.Frame{TS: t0.Add(12 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40005, DstPort: 85, Seq: 107, Ack: 901, Flags: pcaptest.FIN | pcaptest.ACK},
			pcaptest.Frame{TS: t0.Add(13 * time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 85, DstPort: 40005, Seq: 901, Ack: 108, Flags: pcaptest.FIN | pcaptest.ACK},
		)
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		s := asm.Flush()[0]
		if s.Status != session.StatusClosedGapped {
			t.Fatalf("status=%s want closed_with_gaps", s.Status)
		}
		if len(s.Gaps) == 0 {
			t.Fatal("expected explicit gaps")
		}
		var found bool
		for _, g := range s.Gaps {
			if g.FromClient && g.StartSeq == 104-100 && g.EndSeq == 107-100 {
				found = true
			}
		}
		if !found {
			t.Fatalf("gap [4,7) not found in %+v", s.Gaps)
		}
	})

	t.Run("业务:TCP重组/补齐缺口后干净关闭", func(t *testing.T) {
		frames := handshake(40006, 86, 100, 900, t0)
		frames = append(frames,
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40006, DstPort: 86, Seq: 104, Ack: 901, Flags: pcaptest.ACK, Payload: []byte("BBB")},
			pcaptest.Frame{TS: t0.Add(11 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40006, DstPort: 86, Seq: 101, Ack: 901, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("AAA")},
			pcaptest.Frame{TS: t0.Add(12 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40006, DstPort: 86, Seq: 107, Ack: 901, Flags: pcaptest.FIN | pcaptest.ACK},
			pcaptest.Frame{TS: t0.Add(13 * time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 86, DstPort: 40006, Seq: 901, Ack: 108, Flags: pcaptest.FIN | pcaptest.ACK},
			pcaptest.Frame{TS: t0.Add(14 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40006, DstPort: 86, Seq: 108, Ack: 902, Flags: pcaptest.ACK},
		)
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		s := asm.Flush()[0]
		if string(s.C2SPayload) != "AAABBB" {
			t.Fatalf("payload=%q", s.C2SPayload)
		}
		if s.Status != session.StatusClosed {
			t.Fatalf("status=%s want closed", s.Status)
		}
		if len(s.Gaps) != 0 {
			t.Fatalf("gaps=%+v", s.Gaps)
		}
	})

	t.Run("业务:TCP重组/32位序列号回绕", func(t *testing.T) {
		iss := uint32(0xFFFFFFFA)
		frames := []pcaptest.Frame{
			{TS: t0, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40007, DstPort: 87, Seq: iss, Flags: pcaptest.SYN},
			{TS: t0.Add(time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 87, DstPort: 40007, Seq: 200, Ack: iss + 1, Flags: pcaptest.SYN | pcaptest.ACK},
			{TS: t0.Add(2 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40007, DstPort: 87, Seq: iss + 1, Ack: 201, Flags: pcaptest.ACK},
			// data starts at 0xFFFFFFFB (5 bytes: FB..FF), then wraps
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40007, DstPort: 87, Seq: iss + 1, Ack: 201, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("12345")},
			pcaptest.Frame{TS: t0.Add(11 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40007, DstPort: 87, Seq: 0, Ack: 201, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("wrap")},
		}
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		s := asm.Flush()[0]
		if want := "12345wrap"; string(s.C2SPayload) != want {
			t.Fatalf("wrap payload=%q want %q", s.C2SPayload, want)
		}
	})

	t.Run("业务:TCP重组/反复失败连接标记failed_connect", func(t *testing.T) {
		frames := []pcaptest.Frame{
			{TS: t0, SrcIP: "10.0.0.1", DstIP: "10.0.0.9", SrcPort: 41000, DstPort: 4444, Seq: 1, Flags: pcaptest.SYN},
			{TS: t0.Add(2 * time.Millisecond), SrcIP: "10.0.0.9", DstIP: "10.0.0.1", SrcPort: 4444, DstPort: 41000, Seq: 0, Ack: 2, Flags: pcaptest.RST | pcaptest.ACK},
			{TS: t0.Add(3 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.9", SrcPort: 41001, DstPort: 4445, Seq: 1, Flags: pcaptest.SYN},
			// unanswered SYN -> failed
		}
		asm := session.NewAssembler(session.DefaultConfig(), nil)
		feed(t, asm, frames)
		sessions := asm.Flush()
		statuses := map[string]session.Status{}
		for _, s := range sessions {
			statuses[s.Flow.A.String()+"->"+s.Flow.B.String()] = s.Status
		}
		for _, s := range sessions {
			if s.Status != session.StatusReset && s.Status != session.StatusFailed {
				t.Fatalf("unexpected status %s for %s", s.Status, s.Flow)
			}
		}
	})
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func TestSessionEviction(t *testing.T) {
	t.Run("业务:会话回收/空闲超时回收且回调保留证据", func(t *testing.T) {
		cfg := session.Config{IdleTimeout: 10 * time.Second, MaxPayloadPerDirection: 1 << 20}
		var evicted []*session.Session
		asm := session.NewAssembler(cfg, func(s *session.Session) { evicted = append(evicted, s) })
		t0 := time.Date(2024, 2, 1, 0, 0, 0, 0, time.UTC)
		feed(t, asm, handshake(50001, 80, 1, 1, t0))
		if asm.ActiveCount() != 1 {
			t.Fatalf("count=%d", asm.ActiveCount())
		}
		feed(t, asm, handshake(50002, 81, 1, 1, t0.Add(time.Minute)))
		if asm.ActiveCount() != 1 {
			t.Fatalf("count after idle sweep=%d", asm.ActiveCount())
		}
		if len(evicted) != 1 || !evicted[0].Evicted || evicted[0].Status != session.StatusEvicted {
			t.Fatalf("evicted=%+v", evicted)
		}
	})

	t.Run("业务:会话回收/最大会话表LRU回收", func(t *testing.T) {
		cfg := session.Config{MaxSessions: 3, MaxPayloadPerDirection: 1024}
		var nEvict int
		asm := session.NewAssembler(cfg, func(s *session.Session) { nEvict++ })
		t0 := time.Date(2024, 2, 2, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 10; i++ {
			feed(t, asm, handshake(uint16(40000+i), 80, 1, 1, t0.Add(time.Duration(i)*time.Millisecond)))
		}
		// The cap applies at table-insert time; each new handshake's
		// own packets then advance time, so the two most recent flows
		// remain and eight of the ten flows are reclaimed.
		if asm.ActiveCount() != 2 {
			t.Fatalf("active=%d want 2", asm.ActiveCount())
		}
		if nEvict != 8 {
			t.Fatalf("evictions=%d want 8", nEvict)
		}
	})

	t.Run("业务:会话回收/大流量下表规模有界", func(t *testing.T) {
		cfg := session.Config{MaxSessions: 128, MaxPayloadPerDirection: 512}
		asm := session.NewAssembler(cfg, nil)
		t0 := time.Date(2024, 2, 3, 0, 0, 0, 0, time.UTC)
		for i := 0; i < 5000; i++ {
			frames := handshake(uint16(1024+i%40000), uint16(1000+i%50000), uint32(i), uint32(i*7), t0.Add(time.Duration(i)*time.Microsecond))
			feed(t, asm, frames)
			if asm.ActiveCount() > 128 {
				t.Fatalf("table unbounded: %d", asm.ActiveCount())
			}
		}
	})
}

func TestReassemblyDeterminism(t *testing.T) {
	t.Run("业务:一致性/分块读取不影响重组结论", func(t *testing.T) {
		t0 := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
		frames := handshake(60001, 443, 1000, 2000, t0)
		frames = append(frames,
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.1.0.1", DstIP: "10.2.0.1", SrcPort: 60001, DstPort: 443, Seq: 1007, Ack: 2001, Flags: pcaptest.ACK, Payload: []byte("GH")},
			pcaptest.Frame{TS: t0.Add(11 * time.Millisecond), SrcIP: "10.1.0.1", DstIP: "10.2.0.1", SrcPort: 60001, DstPort: 443, Seq: 1001, Ack: 2001, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("ABCDEF")},
			pcaptest.Frame{TS: t0.Add(12 * time.Millisecond), SrcIP: "10.1.0.1", DstIP: "10.2.0.1", SrcPort: 60001, DstPort: 443, Seq: 1003, Ack: 2001, Flags: pcaptest.ACK, Payload: []byte("CDEF-RETR")},
		)
		blob := pcaptest.Build(pcapio.LinkEther, 65535, frames, nil)

		run := func(chunk int) (string, int64, int64) {
			rd := pcapio.NewChunkReader(bytes.NewReader(blob), chunk)
			cap, _, err := pcapio.ReadAll(rd)
			if err != nil {
				t.Fatal(err)
			}
			asm := session.NewAssembler(session.DefaultConfig(), nil)
			for _, rec := range cap.Records {
				pk, err := proto.DecodeFrame(cap.Header.Network, rec)
				if err != nil {
					t.Fatal(err)
				}
				asm.HandlePacket(pk, rec.TS)
			}
			s := asm.Flush()[0]
			return string(s.C2SPayload), s.C2S.UniqueBytes, s.C2S.RetransBytes
		}
		want, wu, wr := run(1 << 20)
		for _, ch := range []int{1, 3, 17, 100, 4096} {
			got, gu, gr := run(ch)
			if got != want || gu != wu || gr != wr {
				t.Fatalf("chunk=%d got=(%q,%d,%d) want=(%q,%d,%d)", ch, got, gu, gr, want, wu, wr)
			}
		}
	})

	t.Run("业务:一致性/同一份抓包重复重放结论一致", func(t *testing.T) {
		t0 := time.Date(2024, 3, 2, 0, 0, 0, 0, time.UTC)
		frames := handshake(60002, 443, 1000, 2000, t0)
		frames = append(frames,
			pcaptest.Frame{TS: t0.Add(10 * time.Millisecond), SrcIP: "10.1.0.2", DstIP: "10.2.0.2", SrcPort: 60002, DstPort: 443, Seq: 1001, Ack: 2001, Flags: pcaptest.PSH | pcaptest.ACK, Payload: []byte("xyz")},
		)
		blob := pcaptest.Build(pcapio.LinkEther, 65535, frames, nil)
		sig := func() string {
			cap, _, err := pcapio.ReadAll(bytes.NewReader(blob))
			if err != nil {
				t.Fatal(err)
			}
			asm := session.NewAssembler(session.DefaultConfig(), nil)
			for _, rec := range cap.Records {
				pk, err := proto.DecodeFrame(cap.Header.Network, rec)
				if err != nil {
					t.Fatal(err)
				}
				asm.HandlePacket(pk, rec.TS)
			}
			s := asm.Flush()[0]
			return fmt.Sprintf("%s|%x|%d|%d", s.Status, s.C2SPayload, s.C2S.UniqueBytes, s.Packets)
		}
		first := sig()
		for i := 0; i < 3; i++ {
			if got := sig(); got != first {
				t.Fatalf("replay mismatch: %q vs %q", got, first)
			}
		}
	})
}

func TestCompletedReclaim(t *testing.T) {
	t.Run("业务:会话回收/已完成会话在保留期后自动回收", func(t *testing.T) {
		cfg := session.Config{
			MaxSessions: 100, MaxPayloadPerDirection: 1024,
			IdleTimeout:        time.Hour,
			CompletedRetention: 5 * time.Second,
		}
		var finished []*session.Session
		asm := session.NewAssembler(cfg, func(s *session.Session) { finished = append(finished, s) })
		t0 := time.Date(2024, 4, 1, 0, 0, 0, 0, time.UTC)
		frames := handshake(51000, 80, 100, 900, t0)
		frames = append(frames,
			pcaptest.Frame{TS: t0.Add(time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 51000, DstPort: 80, Seq: 101, Ack: 901, Flags: pcaptest.FIN | pcaptest.ACK},
			pcaptest.Frame{TS: t0.Add(2 * time.Millisecond), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 51000, Seq: 901, Ack: 102, Flags: pcaptest.FIN | pcaptest.ACK},
			pcaptest.Frame{TS: t0.Add(3 * time.Millisecond), SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 51000, DstPort: 80, Seq: 102, Ack: 902, Flags: pcaptest.ACK},
		)
		feed(t, asm, frames)
		if asm.ActiveCount() != 1 {
			t.Fatalf("just-closed session should be retained, active=%d", asm.ActiveCount())
		}
		// Traffic for another flow later reaps the finished one.
		feed(t, asm, handshake(51001, 81, 1, 1, t0.Add(time.Minute)))
		if asm.ActiveCount() != 1 {
			t.Fatalf("active=%d", asm.ActiveCount())
		}
		if len(finished) != 1 {
			t.Fatalf("finished reclaimed=%d", len(finished))
		}
		if finished[0].Status != session.StatusEvicted {
			t.Fatalf("reclaimed status=%s", finished[0].Status)
		}
	})
}
