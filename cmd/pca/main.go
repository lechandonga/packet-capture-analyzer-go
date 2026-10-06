// Command pca analyzes local pcap/pcapng files without touching a network
// interface. It prints per-file parse status, reassembled session summaries
// and traceable suspicious-behavior findings.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lechandonga/packet-capture-analyzer-go/analyzer"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

func main() {
	jsonOut := flag.Bool("json", false, "emit a JSON report")
	idle := flag.Int64("idle-us", 120_000_000, "idle session timeout in microseconds")
	maxActive := flag.Int("max-active", 100_000, "max live sessions")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] file.pcap [file2.pcap ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	a, err := analyzer.New(nil, session.Config{MaxActive: int(*maxActive), IdleTimeoutUsec: *idle})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	rep := a.AnalyzeBatch(flag.Args())
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	exitOK := true
	for _, r := range rep.Results {
		fmt.Println(r.Summary())
		if r.Error != nil {
			fmt.Printf("  ERROR kind=%s index=%d: %s\n", r.Error.Kind, r.Error.Index, r.Error.Msg)
			exitOK = false
			continue
		}
		for _, s := range r.Sessions {
			fmt.Printf("  session #%d %s:%d -> %s:%d %s gaps=%d retrans=%d bytes=%d\n",
				s.ID, ipStr(s.Init.IP), s.Init.Port, ipStr(s.Resp.IP), s.Resp.Port,
				s.Status, len(s.Gaps), s.Stats.Retransmits, s.Stats.DataBytes)
		}
		for _, f := range r.Findings {
			fmt.Printf("  FINDING %s (%s) subject=%s value=%d evidence=%d ruleset=v%d\n",
				f.RuleID, f.RuleType, f.Subject, f.Value, len(f.Evidence), f.RuleVersion)
		}
	}
	if !exitOK {
		os.Exit(3)
	}
}

func ipStr(ip []byte) string {
	out := make([]byte, 0, 16)
	for i, b := range ip {
		if i > 0 {
			out = append(out, '.')
		}
		out = append(out, fmt.Appendf(nil, "%d", b)...)
	}
	return string(out)
}
