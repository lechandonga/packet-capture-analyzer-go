// Command pcap-analyze runs the offline packet-capture analyzer against
// local pcap files and prints a JSON report. It never opens a network
// interface and requires no special privileges.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lechandonga/packet-capture-analyzer-go/analyzer"
	"github.com/lechandonga/packet-capture-analyzer-go/detect"
)

func main() {
	rulesFile := flag.String("rules", "", "path to a JSON rule set (default: built-in rules)")
	ruleVersion := flag.Int("rule-version", 1, "version label installed with -rules")
	idleTimeout := flag.Duration("idle-timeout", 0, "override session idle timeout (e.g. 5m)")
	maxSessions := flag.Int("max-sessions", 0, "override maximum live sessions")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s [flags] file.pcap [file2.pcap ...]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	engine := detect.NewDefaultEngine()
	if *rulesFile != "" {
		raw, err := os.ReadFile(*rulesFile)
		if err != nil {
			fatal("read rules", err)
		}
		if err := engine.ParseAndUpdate(*ruleVersion, raw); err != nil {
			fatal("install rules", err)
		}
	}

	cfg := analyzer.DefaultConfig()
	if *idleTimeout > 0 {
		cfg.Session.IdleTimeout = *idleTimeout
	}
	if *maxSessions > 0 {
		cfg.Session.MaxSessions = *maxSessions
	}
	az := analyzer.New(engine, cfg)
	report := az.AnalyzeFiles(flag.Args())

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		fatal("write report", err)
	}
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
	os.Exit(1)
}
