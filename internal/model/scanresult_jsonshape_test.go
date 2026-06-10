package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestScanResult_NewAuditFields_OmitWhenNil locks in the PR-#134 fix:
// when feature gates are off, the scanner sets PnpmAudit/BunAudit/YarnAudit
// to nil so the JSON output drops the field entirely rather than emitting
// `{"files": null, "env": null, ...}`.
func TestScanResult_NewAuditFields_OmitWhenNil(t *testing.T) {
	r := &ScanResult{}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, key := range []string{`"pnpm_audit"`, `"bun_audit"`, `"yarn_audit"`} {
		if strings.Contains(s, key) {
			t.Errorf("zero ScanResult should omit %s, got: %s", key, s)
		}
	}
}
