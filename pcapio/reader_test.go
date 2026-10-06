package pcapio_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio/pcaptest"
)

func globalHeader(bo binary.ByteOrder, magic uint32, link pcapio.LinkType) []byte {
	h := make([]byte, 24)
	bo.PutUint32(h[0:4], magic)
	bo.PutUint16(h[4:6], 2)
	bo.PutUint16(h[6:8], 4)
	bo.PutUint32(h[16:20], 65535)
	bo.PutUint32(h[20:24], uint32(link))
	return h
}

func TestPCAPReader(t *testing.T) {
	t.Run("业务:pcap解析/小端微秒往返与常见链路类型", func(t *testing.T) {
		for _, link := range []pcapio.LinkType{pcapio.LinkEther, pcapio.LinkNull, pcapio.LinkRaw, pcapio.LinkLinux} {
			frames := []pcaptest.Frame{
				{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1111, DstPort: 80, Seq: 100, Flags: pcaptest.SYN},
				{SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 80, DstPort: 1111, Seq: 500, Ack: 101, Flags: pcaptest.SYN | pcaptest.ACK},
			}
			blob := pcaptest.Build(link, 65535, frames, nil)
			cap, recErrs, err := pcapio.ReadAll(bytes.NewReader(blob))
			if err != nil || len(recErrs) != 0 {
				t.Fatalf("link=%s err=%v recErrs=%v", link, err, recErrs)
			}
			if cap.Header.Network != link || len(cap.Records) != 2 {
				t.Fatalf("link=%s network=%s records=%d", link, cap.Header.Network, len(cap.Records))
			}
			if cap.Records[1].Index != 1 {
				t.Fatalf("record index: %d", cap.Records[1].Index)
			}
		}
	})

	t.Run("业务:pcap解析/大端纳秒时间戳精度", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(globalHeader(binary.BigEndian, 0xa1b23c4d, pcapio.LinkEther))
		pkt := pcaptest.EthernetIPv4TCP(pcaptest.Frame{
			SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, Flags: pcaptest.SYN,
		})
		rec := make([]byte, 16+len(pkt))
		binary.BigEndian.PutUint32(rec[0:4], 1700000000)
		binary.BigEndian.PutUint32(rec[4:8], 123456789)
		binary.BigEndian.PutUint32(rec[8:12], uint32(len(pkt)))
		binary.BigEndian.PutUint32(rec[12:16], uint32(len(pkt)))
		copy(rec[16:], pkt)
		buf.Write(rec)

		cap, _, err := pcapio.ReadAll(&buf)
		if err != nil {
			t.Fatal(err)
		}
		want := time.Unix(1700000000, 123456789).UTC()
		if !cap.Records[0].TS.Equal(want) {
			t.Fatalf("nanosecond ts=%v want %v", cap.Records[0].TS, want)
		}
	})

	t.Run("业务:pcap解析/snaplen截断标记", func(t *testing.T) {
		frames := []pcaptest.Frame{
			{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 2, Seq: 1, Flags: pcaptest.ACK, Payload: make([]byte, 100)},
		}
		blob := pcaptest.Build(pcapio.LinkEther, 60, frames, nil)
		cap, _, err := pcapio.ReadAll(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		if !cap.Records[0].Truncated() || uint32(len(cap.Records[0].Data)) != 60 {
			t.Fatalf("truncated=%v len=%d", cap.Records[0].Truncated(), len(cap.Records[0].Data))
		}
	})

	t.Run("业务:pcap解析/错误分类-坏魔数", func(t *testing.T) {
		bad := globalHeader(binary.LittleEndian, 0xdeadbeef, pcapio.LinkEther)
		_, _, err := pcapio.ReadAll(bytes.NewReader(bad))
		var fe *pcapio.FileError
		if !errors.As(err, &fe) || fe.Kind != pcapio.ErrBadMagic {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("业务:pcap解析/错误分类-不支持版本", func(t *testing.T) {
		h := globalHeader(binary.LittleEndian, 0xa1b2c3d4, pcapio.LinkEther)
		binary.LittleEndian.PutUint16(h[4:6], 1)
		_, _, err := pcapio.ReadAll(bytes.NewReader(h))
		var fe *pcapio.FileError
		if !errors.As(err, &fe) || fe.Kind != pcapio.ErrUnsupportedVersion {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("业务:pcap解析/错误分类-不支持链路类型", func(t *testing.T) {
		h := globalHeader(binary.LittleEndian, 0xa1b2c3d4, pcapio.LinkType(999))
		_, _, err := pcapio.ReadAll(bytes.NewReader(h))
		var fe *pcapio.FileError
		if !errors.As(err, &fe) || fe.Kind != pcapio.ErrUnsupportedLink {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("业务:pcap解析/错误分类-文件截断", func(t *testing.T) {
		good := pcaptest.Build(pcapio.LinkEther, 65535, []pcaptest.Frame{
			{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, Flags: pcaptest.SYN},
		}, nil)
		for _, cut := range []int{0, 7, 23, 24 + 5} {
			_, _, err := pcapio.ReadAll(bytes.NewReader(good[:cut]))
			var fe *pcapio.FileError
			if !errors.As(err, &fe) || fe.Kind != pcapio.ErrTruncatedFile {
				t.Fatalf("cut=%d err=%v", cut, err)
			}
		}
	})

	t.Run("业务:pcap解析/错误分类-畸形记录incl>orig", func(t *testing.T) {
		frames := []pcaptest.Frame{
			{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, Flags: pcaptest.SYN, Bad: pcaptest.BadInclOverOrig},
		}
		cap, _, err := pcapio.ReadAll(bytes.NewReader(pcaptest.Build(pcapio.LinkEther, 65535, frames, nil)))
		var fe *pcapio.FileError
		if !errors.As(err, &fe) || fe.Kind != pcapio.ErrTruncatedFile {
			t.Fatalf("err=%v", err)
		}
		if cap == nil || len(cap.Records) != 0 {
			t.Fatalf("capture records before corruption: %+v", cap)
		}
	})

	t.Run("业务:pcap解析/错误分类-记录体截断拖垮剩余字节", func(t *testing.T) {
		frames := []pcaptest.Frame{
			{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, Flags: pcaptest.SYN, Bad: pcaptest.BadTruncatedRecord},
		}
		cap, recErrs, err := pcapio.ReadAll(bytes.NewReader(pcaptest.Build(pcapio.LinkEther, 65535, frames, nil)))
		if err == nil && len(recErrs) == 0 {
			t.Fatal("expected corruption signal")
		}
		if cap != nil {
			// header may have been read
		}
	})

	t.Run("业务:pcap解析/重复解析结果一致", func(t *testing.T) {
		blob := pcaptest.Build(pcapio.LinkEther, 65535, []pcaptest.Frame{
			{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 2, Seq: 1, Flags: pcaptest.SYN},
			{SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 2, DstPort: 1, Seq: 9, Ack: 2, Flags: pcaptest.SYN | pcaptest.ACK},
		}, nil)
		first, _, err := pcapio.ReadAll(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		second, _, err := pcapio.ReadAll(bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		if len(first.Records) != len(second.Records) {
			t.Fatal("record count differs")
		}
		for i := range first.Records {
			a, b := first.Records[i], second.Records[i]
			if !a.TS.Equal(b.TS) || a.InclLen != b.InclLen || a.OrigLen != b.OrigLen || !bytes.Equal(a.Data, b.Data) {
				t.Fatalf("record %d differs across parses", i)
			}
		}
	})

	t.Run("业务:pcap解析/分块读取边界不影响结论", func(t *testing.T) {
		blob := pcaptest.Build(pcapio.LinkEther, 65535, []pcaptest.Frame{
			{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 2, Seq: 1, Flags: pcaptest.SYN},
			{SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 2, DstPort: 1, Seq: 9, Ack: 2, Flags: pcaptest.SYN | pcaptest.ACK},
		}, nil)
		for _, chunk := range []int{1, 7, 16, 33, 4096} {
			rd := pcapio.NewChunkReader(bytes.NewReader(blob), chunk)
			cap, _, err := pcapio.ReadAll(rd)
			if err != nil || len(cap.Records) != 2 {
				t.Fatalf("chunk=%d err=%v records=%d", chunk, err, len(cap.Records))
			}
		}
	})

	t.Run("业务:pcap解析/批处理-坏文件不拖垮其它文件", func(t *testing.T) {
		dir := t.TempDir()
		goodPath := filepath.Join(dir, "good.pcap")
		badPath := filepath.Join(dir, "bad.pcap")
		missingPath := filepath.Join(dir, "missing.pcap")
		good := pcaptest.Build(pcapio.LinkEther, 65535, []pcaptest.Frame{
			{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", SrcPort: 1, DstPort: 2, Flags: pcaptest.SYN},
		}, nil)
		if err := os.WriteFile(goodPath, good, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(badPath, []byte("not a pcap file!!"), 0o644); err != nil {
			t.Fatal(err)
		}
		results := pcapio.ProcessFiles([]string{goodPath, badPath, missingPath})
		if len(results) != 3 {
			t.Fatalf("results=%d", len(results))
		}
		if results[0].Err != nil || results[0].Capture == nil || len(results[0].Capture.Records) != 1 {
			t.Fatalf("good file broken: %+v", results[0])
		}
		var fe *pcapio.FileError
		if !errors.As(results[1].Err, &fe) || fe.Kind != pcapio.ErrBadMagic {
			t.Fatalf("bad file err=%v", results[1].Err)
		}
		var oe *pcapio.OpenError
		if !errors.As(results[2].Err, &oe) {
			t.Fatalf("missing file err=%v", results[2].Err)
		}
	})

	t.Run("业务:pcap解析/空文件为截断错误而非成功", func(t *testing.T) {
		_, _, err := pcapio.ReadAll(bytes.NewReader(nil))
		var fe *pcapio.FileError
		if !errors.As(err, &fe) || fe.Kind != pcapio.ErrTruncatedFile {
			t.Fatalf("err=%v", err)
		}
	})

	_ = io.EOF
}
