package detect_test

import (
	"bytes"
	"encoding/json"

	"github.com/lechandonga/packet-capture-analyzer-go/detect"
	"github.com/lechandonga/packet-capture-analyzer-go/pcapio"
)

func readAll(b []byte) (*pcapio.Capture, []*pcapio.RecordError, error) {
	return pcapio.ReadAll(bytes.NewReader(b))
}

func containsKind(kinds []detect.RuleKind, want detect.RuleKind) bool {
	for _, k := range kinds {
		if k == want {
			return true
		}
	}
	return false
}

func jsonMarshal(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	return b, err
}

func sig(fs []detect.Finding) string {
	b, _ := json.Marshal(fs)
	return string(b)
}
