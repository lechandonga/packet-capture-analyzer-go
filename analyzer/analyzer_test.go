package analyzer_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/analyzer"
	"github.com/lechandonga/packet-capture-analyzer-go/detect"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio/pcaptest"
)

func TestPipeline(t *testing.T) {
	base := time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)

	t.Run("业务:端到端/畸形记录上报且不中断同文件后续分析", func(t *testing.T) {
		frames := []pcaptest.Frame{
			{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 2, Seq: 1, Flags: pcaptest.SYN},
			{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 3, DstPort: 4, Seq: 1, Flags: pcaptest.SYN, Bad: pcaptest.BadInclOverOrig},
		}
		blob := pcaptest.Build(pcapio.LinkEther, 65535, frames, nil)
		az := analyzer.New(detect.NewDefaultEngine(), analyzer.DefaultConfig())
		rep := az.AnalyzeCapture("mem.pcap", blob)
		if rep.ParseError == "" {
			t.Fatal("expected parse error for desynced capture")
		}
		if rep.RecordCount != 1 {
			t.Fatalf("records=%d", rep.RecordCount)
		}
	})

	t.Run("业务:端到端/截断帧按层上报为PacketIssue", func(t *testing.T) {
		frames := []pcaptest.Frame{
			{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 2, Seq: 1, Flags: pcaptest.SYN, Payload: make([]byte, 200)},
		}
		blob := pcaptest.Build(pcapio.LinkEther, 40, frames, nil)
		az := analyzer.New(detect.NewDefaultEngine(), analyzer.DefaultConfig())
		rep := az.AnalyzeCapture("snap.pcap", blob)
		if len(rep.PacketIssues) != 1 || rep.PacketIssues[0].Layer != "tcp" {
			t.Fatalf("issues=%+v", rep.PacketIssues)
		}
	})

	t.Run("业务:端到端/批处理坏文件不拖垮好文件", func(t *testing.T) {
		dir := t.TempDir()
		var scanFrames []pcaptest.Frame
		for i := 0; i < 12; i++ {
			scanFrames = append(scanFrames, pcaptest.Frame{
				TS:    base.Add(time.Duration(i) * time.Second),
				SrcIP: "10.7.0.1", DstIP: "10.7.0.2",
				SrcPort: uint16(40000 + i), DstPort: uint16(2000 + i), Seq: 1, Flags: pcaptest.SYN,
			})
		}
		good := pcaptest.Build(pcapio.LinkEther, 65535, scanFrames, nil)
		goodPath := filepath.Join(dir, "scan.pcap")
		badPath := filepath.Join(dir, "corrupt.pcap")
		if err := os.WriteFile(goodPath, good, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(badPath, []byte("garbage"), 0o644); err != nil {
			t.Fatal(err)
		}
		az := analyzer.New(detect.NewDefaultEngine(), analyzer.DefaultConfig())
		report := az.AnalyzeFiles([]string{badPath, goodPath})
		if len(report.Files) != 2 {
			t.Fatalf("files=%d", len(report.Files))
		}
		if report.Files[0].ParseError == "" {
			t.Fatal("corrupt file not flagged")
		}
		if report.Files[1].ParseError != "" || len(report.Files[1].Sessions) != 12 {
			t.Fatalf("good file sessions=%d err=%s", len(report.Files[1].Sessions), report.Files[1].ParseError)
		}
		if len(report.Findings) == 0 {
			t.Fatal("cross-file findings missing")
		}
		if report.Files[1].FindingCount == 0 {
			t.Fatal("per-file finding count not attributed")
		}
	})

	t.Run("业务:端到端/同批重复运行报告结论稳定", func(t *testing.T) {
		dir := t.TempDir()
		var frames []pcaptest.Frame
		for i := 0; i < 12; i++ {
			frames = append(frames, pcaptest.Frame{
				TS:    base.Add(time.Duration(i) * time.Second),
				SrcIP: "10.7.1.1", DstIP: "10.7.1.2",
				SrcPort: uint16(40000 + i), DstPort: uint16(3000 + i), Seq: 1, Flags: pcaptest.SYN,
			})
		}
		path := filepath.Join(dir, "x.pcap")
		if err := os.WriteFile(path, pcaptest.Build(pcapio.LinkEther, 65535, frames, nil), 0o644); err != nil {
			t.Fatal(err)
		}
		az := analyzer.New(detect.NewDefaultEngine(), analyzer.DefaultConfig())
		sig1 := stableSig(t, az.AnalyzeFiles([]string{path}))
		sig2 := stableSig(t, az.AnalyzeFiles([]string{path}))
		if sig1 != sig2 {
			t.Fatalf("reports differ:\n%s\n%s", sig1, sig2)
		}
	})
}
