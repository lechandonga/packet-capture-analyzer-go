// Package analyzer ties capture parsing, session reassembly and rule-based
// detection together for local pcap files. Batch analysis isolates files: a
// corrupt capture never affects results of the others.
package analyzer

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/lechandonga/packet-capture-analyzer-go/detect"
	"github.com/lechandonga/packet-capture-analyzer-go/pcap"
	"github.com/lechandonga/packet-capture-analyzer-go/rules"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

// FileResult is the complete, explainable result for one file.
type FileResult struct {
	Path     string
	Format   pcap.Format
	Link     pcap.LinkType
	Sessions []*session.Session
	Findings []detect.Finding
	Read     pcap.Stats
	// Error is nil for a fully consumed file; otherwise the classified
	// parse error. Sessions decoded before the failure are retained.
	Error *pcap.ParseError
	// RuleVersion is the exact snapshot used for this file's conclusions.
	RuleVersion int
}

// Report aggregates a batch.
type Report struct {
	Results []FileResult
}

// Analyzer processes files against an atomic rule store.
type Analyzer struct {
	store *rules.Store
	cfg   session.Config
}

// New creates an Analyzer. If store is nil, built-in rules are used.
func New(store *rules.Store, cfg session.Config) (*Analyzer, error) {
	if store == nil {
		var err error
		store, err = rules.NewStore(rules.DefaultRules())
		if err != nil {
			return nil, err
		}
	}
	return &Analyzer{store: store, cfg: cfg}, nil
}

// AnalyzeReader runs one full analysis on an in-memory stream. The ruleset
// snapshot is taken once up front, so rule updates during the run cannot mix
// versions in the returned findings.
func (a *Analyzer) AnalyzeReader(path string, r io.Reader) FileResult {
	snapshot := a.store.Current()
	res := FileResult{Path: path, RuleVersion: snapshot.Version}

	pr, err := pcap.NewReader(r)
	if err != nil {
		if pe, ok := err.(*pcap.ParseError); ok {
			res.Error = pe
		} else {
			res.Error = &pcap.ParseError{Kind: pcap.KindCorrupt, Index: -1, Msg: err.Error()}
		}
		return res
	}
	res.Format = pr.Format()
	res.Link = pr.Link()

	eng := session.NewEngine(a.cfg)
	det := detect.New(snapshot)

	for {
		pkt, rerr := pr.Read()
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			if pe, ok := rerr.(*pcap.ParseError); ok {
				res.Error = pe
			} else {
				res.Error = &pcap.ParseError{Kind: pcap.KindCorrupt, Index: -1, Msg: rerr.Error()}
			}
			break
		}
		eng.HandlePacket(pkt)
	}
	for _, s := range eng.Flush() {
		det.Observe(s)
	}
	res.Sessions = eng.Flush()
	res.Findings = det.Finalize()
	res.Read = pr.Stats()
	return res
}

// AnalyzeFile reads one file from disk.
func (a *Analyzer) AnalyzeFile(path string) FileResult {
	f, err := os.Open(path)
	if err != nil {
		return FileResult{
			Path:        path,
			RuleVersion: a.store.Current().Version,
			Error:       &pcap.ParseError{Kind: pcap.KindTruncatedHeader, Index: -1, Msg: err.Error()},
		}
	}
	defer f.Close()
	return a.AnalyzeReader(path, f)
}

// AnalyzeBytes is a convenience helper for embedded/bytes captures (tests).
func (a *Analyzer) AnalyzeBytes(path string, data []byte) FileResult {
	return a.AnalyzeReader(path, bytes.NewReader(data))
}

// AnalyzeBatch processes several files independently; one file's parse error
// never prevents the others from being analyzed.
func (a *Analyzer) AnalyzeBatch(paths []string) *Report {
	rep := &Report{Results: make([]FileResult, 0, len(paths))}
	for _, p := range paths {
		rep.Results = append(rep.Results, a.AnalyzeFile(p))
	}
	sort.SliceStable(rep.Results, func(i, j int) bool { return rep.Results[i].Path < rep.Results[j].Path })
	return rep
}

// Summary renders a short human-readable line.
func (f FileResult) Summary() string {
	status := "ok"
	if f.Error != nil {
		status = string(f.Error.Kind)
	}
	return fmt.Sprintf("%s: format=%s sessions=%d findings=%d read=%s status=%s rules=v%d",
		f.Path, f.Format, len(f.Sessions), len(f.Findings),
		fmt.Sprintf("decoded=%d skipped=%d", f.Read.Decoded, f.Read.Skipped),
		status, f.RuleVersion)
}
