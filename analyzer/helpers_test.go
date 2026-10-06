package analyzer_test

import (
	"encoding/json"
	"testing"

	"github.com/lechandonga/packet-capture-analyzer-go/analyzer"
)

func stableSig(t *testing.T, r *analyzer.Report) string {
	t.Helper()
	r.GeneratedAt = ""
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
