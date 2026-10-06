package pcapio

import (
	"errors"
	"os"
)

// FileResult is the outcome of processing one file in a batch. Exactly
// one of Capture/Err is authoritative for file-level parsing; RecordErrs
// collects distinguishable per-record problems without dropping data.
type FileResult struct {
	Path       string
	Capture    *Capture
	RecordErrs []*RecordError
	Err        error
}

// OpenError reports that a file could not be opened at all.
type OpenError struct {
	Path string
	Err  error
}

func (e *OpenError) Error() string { return "open " + e.Path + ": " + e.Err.Error() }
func (e *OpenError) Unwrap() error { return e.Err }

// ReadFile parses a single local pcap file.
func ReadFile(path string) (*Capture, []*RecordError, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, &OpenError{Path: path, Err: err}
	}
	defer f.Close()
	cap, recErrs, err := ReadAll(f)
	return cap, recErrs, err
}

// ProcessFiles parses a batch of files independently: a corrupt or
// missing file never aborts the others. Results are returned in the same
// order as the input paths so repeated runs are stable.
func ProcessFiles(paths []string) []FileResult {
	out := make([]FileResult, 0, len(paths))
	for _, p := range paths {
		res := FileResult{Path: p}
		cap, recErrs, err := ReadFile(p)
		res.Capture = cap
		res.RecordErrs = recErrs
		res.Err = err
		out = append(out, res)
	}
	return out
}

// IsFatal reports whether a file-level error makes the whole capture
// unusable (as opposed to isolated damaged records).
func IsFatal(err error) bool {
	var fe *FileError
	if errors.As(err, &fe) {
		switch fe.Kind {
		case ErrBadMagic, ErrUnsupportedVersion, ErrUnsupportedLink:
			return true
		}
	}
	return false
}
