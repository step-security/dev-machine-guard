package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// TestWriteTelemetryFile asserts the dev-only --telemetry-out dump produces a
// valid Payload JSON file (§8.1/§8.4) that round-trips, including the additive
// rule_scan field — i.e. the exact shape the backend's process-uploaded ingests.
func TestWriteTelemetryFile(t *testing.T) {
	payload := &Payload{
		CustomerID: "cust",
		DeviceID:   "dev-123",
		RuleScan: &model.RuleScan{
			ScanComplete: true,
			EvaluatedRules: []model.EvaluatedRule{
				{RuleID: "github-setup-js-dropper", RuleRevision: "a1b2c3", Complete: true},
			},
			Results: []model.RuleResult{{
				RuleID:       "github-setup-js-dropper",
				RuleRevision: "a1b2c3",
				Files: []model.RuleFileMatch{{
					Path:        "/Users/dev/acme/.github/setup.js",
					MatchedGlob: "**/.github/setup.js",
					FileSHA256:  "5926b8",
					Groups: []model.GroupResult{{
						GroupID: "dropper-signatures", FullMatch: false,
						Conditions: []model.ConditionResult{{ID: "aes-gcm", Kind: "regex", Matched: true}},
					}},
					FileAttrs: model.FileAttrs{SizeBytes: 4500, ModifiedAt: 1733500800},
				}},
			}},
		},
	}

	path := filepath.Join(t.TempDir(), "payload.json")
	if err := writeTelemetryFile(path, payload); err != nil {
		t.Fatalf("writeTelemetryFile: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Payload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("dumped file is not valid Payload JSON: %v", err)
	}
	if got.DeviceID != "dev-123" {
		t.Errorf("DeviceID = %q", got.DeviceID)
	}
	if got.RuleScan == nil || !got.RuleScan.ScanComplete {
		t.Fatalf("rule_scan did not round-trip: %+v", got.RuleScan)
	}
	if len(got.RuleScan.Results) != 1 || got.RuleScan.Results[0].RuleRevision != "a1b2c3" {
		t.Errorf("rule_scan results not preserved: %+v", got.RuleScan.Results)
	}
}

// TestWriteTelemetryFile_NilRuleScanOmitted confirms a run that did not scan
// (ruleScan stays nil) omits rule_scan entirely — the backend's "not scanned"
// signal (D10).
func TestWriteTelemetryFile_NilRuleScanOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "payload.json")
	if err := writeTelemetryFile(path, &Payload{CustomerID: "c", DeviceID: "d"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, present := raw["rule_scan"]; present {
		t.Error("rule_scan should be omitted when nil")
	}
}
