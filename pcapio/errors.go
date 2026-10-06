package pcapio

import "fmt"

// ErrorKind gives a stable, distinguishable reason for a parse failure.
type ErrorKind string

const (
	ErrBadMagic           ErrorKind = "bad_magic"
	ErrUnsupportedVersion ErrorKind = "unsupported_version"
	ErrUnsupportedLink    ErrorKind = "unsupported_link_type"
	ErrTruncatedFile      ErrorKind = "truncated_file"
	ErrIOFailure          ErrorKind = "io_failure"

	ErrBadRecordLength  ErrorKind = "bad_record_length"
	ErrInclExceedsOrig  ErrorKind = "incl_len_exceeds_orig_len"
	ErrRecordBeyondSnap ErrorKind = "record_exceeds_snaplen"
	ErrTruncatedRecord  ErrorKind = "truncated_record"
)

// FileError describes a fatal problem with the capture as a whole.
type FileError struct {
	Kind   ErrorKind
	Detail string
	Err    error
}

func (e *FileError) Error() string {
	s := "pcap file error: " + string(e.Kind)
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *FileError) Unwrap() error { return e.Err }

// RecordError describes one damaged record. Index is its position in the
// capture (zero based, counting damaged records too).
type RecordError struct {
	Index  int64
	Kind   ErrorKind
	Detail string
	Err    error
}

func (e *RecordError) Error() string {
	s := fmt.Sprintf("pcap record #%d error: %s", e.Index, e.Kind)
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

func (e *RecordError) Unwrap() error { return e.Err }
