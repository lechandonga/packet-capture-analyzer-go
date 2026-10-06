// Package analyzer wires pcap parsing, protocol decoding, TCP/UDP
// reassembly and rule-based behavior detection into one deterministic,
// offline pipeline.
package analyzer

import (
	"bytes"
	"sort"
	"sync"
	"time"

	"github.com/lechandonga/packet-capture-analyzer-go/detect"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
	"github.com/lechandonga/packet-capture-analyzer-go/proto"
	"github.com/lechandonga/packet-capture-analyzer-go/session"
)

// PacketIssue explains why one record was not analyzed. It is reported
// rather than silently skipped.
type PacketIssue struct {
	Record int64
	Layer  string
	Reason string
	Detail string
}

// FileReport is the complete result for one capture file.
type FileReport struct {
	Path         string
	ParseError   string
	RecordErrors []string
	PacketIssues []PacketIssue
	RecordCount  int
	AnalyzedTCP  int
	AnalyzedUDP  int
	Sessions     []*session.Session
	FindingCount int
}

// Report aggregates one processing run (one or more files).
type Report struct {
	RuleVersion int
	GeneratedAt string
	Files       []*FileReport
	Findings    []detect.Finding
}

// Config tunes the pipeline.
type Config struct {
	Session session.Config
}

// DefaultConfig returns pipeline defaults.
func DefaultConfig() Config {
	return Config{Session: session.DefaultConfig()}
}

// Analyzer is safe for concurrent Analyze* calls against the same engine;
// each call owns its private reassembler.
type Analyzer struct {
	engine *detect.Engine
	cfg    Config
}

// New creates a pipeline bound to a rule engine.
func New(engine *detect.Engine, cfg Config) *Analyzer {
	return &Analyzer{engine: engine, cfg: cfg}
}

// AnalyzeCapture parses raw pcap bytes and runs the full pipeline. Chunk
// boundaries in the input reader do not affect results.
func (a *Analyzer) AnalyzeCapture(name string, pcapBytes []byte) *FileReport {
	cap, recErrs, err := pcapio.ReadAll(bytes.NewReader(pcapBytes))
	rep := &FileReport{Path: name}
	if err != nil {
		rep.ParseError = err.Error()
	}
	for _, re := range recErrs {
		rep.RecordErrors = append(rep.RecordErrors, re.Error())
	}
	if cap == nil {
		return rep
	}
	return a.finish(rep, cap)
}

// AnalyzeFile processes one local pcap file.
func (a *Analyzer) AnalyzeFile(path string) *FileReport {
	cap, recErrs, err := pcapio.ReadFile(path)
	rep := &FileReport{Path: path}
	if err != nil {
		rep.ParseError = err.Error()
	}
	for _, re := range recErrs {
		rep.RecordErrors = append(rep.RecordErrors, re.Error())
	}
	if cap == nil {
		return rep
	}
	return a.finish(rep, cap)
}

// AnalyzeFiles processes a batch independently: one file's failure never
// prevents the others from being parsed and analyzed.
func (a *Analyzer) AnalyzeFiles(paths []string) *Report {
	report := &Report{
		RuleVersion: a.engine.ActiveVersion(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	var allSessions []*session.Session
	for _, p := range paths {
		fr := a.AnalyzeFile(p)
		report.Files = append(report.Files, fr)
		allSessions = append(allSessions, fr.Sessions...)
	}
	report.Findings = a.engine.Analyze(allSessions)
	for _, f := range report.Files {
		f.FindingCount = findingsForFile(report.Findings, f)
	}
	return report
}

func findingsForFile(all []detect.Finding, f *FileReport) int {
	keys := map[string]bool{}
	for _, s := range f.Sessions {
		keys[s.Flow.String()] = true
	}
	n := 0
	for _, x := range all {
		for _, k := range x.Evidence.SessionKeys {
			if keys[k] {
				n++
				break
			}
		}
	}
	return n
}

func (a *Analyzer) finish(rep *FileReport, cap *pcapio.Capture) *FileReport {
	var mu sync.Mutex
	var finished []*session.Session
	asm := session.NewAssembler(a.cfg.Session, func(s *session.Session) {
		mu.Lock()
		finished = append(finished, s)
		mu.Unlock()
	})
	rep.RecordCount = len(cap.Records)
	for _, rec := range cap.Records {
		pk, err := proto.DecodeFrame(cap.Header.Network, rec)
		if err != nil {
			issue := PacketIssue{Record: rec.Index, Reason: err.Error()}
			var de *proto.DecodeError
			if asDecode(err, &de) {
				issue.Layer = de.Layer
				issue.Record = de.Record
			}
			rep.PacketIssues = append(rep.PacketIssues, issue)
			continue
		}
		if pk.TCP != nil {
			rep.AnalyzedTCP++
		} else {
			rep.AnalyzedUDP++
		}
		asm.HandlePacket(pk, rec.TS)
	}
	rep.Sessions = append(finished, asm.Flush()...)
	sort.Slice(rep.Sessions, func(i, j int) bool {
		if !rep.Sessions[i].FirstTS.Equal(rep.Sessions[j].FirstTS) {
			return rep.Sessions[i].FirstTS.Before(rep.Sessions[j].FirstTS)
		}
		return rep.Sessions[i].Flow.String() < rep.Sessions[j].Flow.String()
	})
	sort.Slice(rep.PacketIssues, func(i, j int) bool {
		return rep.PacketIssues[i].Record < rep.PacketIssues[j].Record
	})
	return rep
}

func asDecode(err error, target **proto.DecodeError) bool {
	for err != nil {
		if de, ok := err.(*proto.DecodeError); ok {
			*target = de
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// RunFindings evaluates findings for a single-file report.
func (a *Analyzer) RunFindings(fr *FileReport) []detect.Finding {
	return a.engine.Analyze(fr.Sessions)
}
