package telemetry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
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

func TestWriteTelemetryFileAgentPlugins(t *testing.T) {
	raw, err := os.ReadFile("../model/testdata/agent_plugins_v1_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var payload Payload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	payload.CustomerID, payload.DeviceID = "example-customer", "example-device"
	payload.WSLGuest = &model.WSLGuest{HostDeviceID: "example-host", DistroID: "example-distro"}
	payload.PayloadSchemaVersion = CurrentPayloadSchemaVersion
	payload.NodeProjectsUnchanged = []model.UnchangedProjectRef{{Path: "/example", ScanOutputHash: "sha256:example", LastUploadedExecutionID: "previous"}}
	file := filepath.Join(t.TempDir(), "payload.json")
	if err := writeTelemetryFile(file, &payload); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var got Payload
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.AgentPlugins, payload.AgentPlugins) || !reflect.DeepEqual(got.AgentSkills, payload.AgentSkills) || !reflect.DeepEqual(got.AgentSkillScan, payload.AgentSkillScan) {
		t.Fatal("telemetry output lost agent plugin or skill usage fields")
	}
	if !reflect.DeepEqual(got.WSLGuest, payload.WSLGuest) || !reflect.DeepEqual(got.NodeProjectsUnchanged, payload.NodeProjectsUnchanged) || got.PayloadSchemaVersion != CurrentPayloadSchemaVersion {
		t.Fatal("agent plugins changed guest or package delta fields")
	}
	data, err = json.Marshal(&Payload{})
	if err != nil {
		t.Fatal(err)
	}
	var empty map[string]json.RawMessage
	if err := json.Unmarshal(data, &empty); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"agent_plugins", "agent_skill_usage_scan"} {
		if _, exists := empty[key]; exists {
			t.Errorf("unrun section %s was emitted", key)
		}
	}
}
