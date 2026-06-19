package telemetry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestPayload_LegacyShapeOmitsDeltaFields(t *testing.T) {
	p := &Payload{
		CustomerID: "c",
		DeviceID:   "d",
		NodeProjects: []model.NodeScanResult{
			{ProjectPath: "/svc", PackageManager: "npm"},
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if strings.Contains(s, "payload_schema_version") {
		t.Errorf("legacy payload (schema=0) should omit payload_schema_version: %s", s)
	}
	for _, field := range []string{
		"node_projects_unchanged", "node_projects_removed", "node_globals_unchanged",
		"python_projects_unchanged", "python_projects_removed", "python_globals_unchanged",
	} {
		if strings.Contains(s, field) {
			t.Errorf("legacy payload should omit %q field, but it's present", field)
		}
	}
}

func TestPayload_DeltaShapeShipsRefSlices(t *testing.T) {
	p := &Payload{
		PayloadSchemaVersion: CurrentPayloadSchemaVersion,
		CustomerID:           "c",
		DeviceID:             "d",
		NodeProjects: []model.NodeScanResult{
			{ProjectPath: "/changed-svc", PackageManager: "npm"},
		},
		NodeProjectsUnchanged: []model.UnchangedProjectRef{
			{Path: "/unchanged-svc", ScanOutputHash: "sha256:abc", LastUploadedExecutionID: "exec-1"},
		},
		NodeProjectsRemoved: []model.RemovedProjectRef{
			{Path: "/removed-svc", LastUploadedExecutionID: "exec-0"},
		},
		NodeGlobalsUnchanged: []model.UnchangedGlobalRef{
			{PackageManager: "npm", ScanOutputHash: "sha256:def"},
		},
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`"payload_schema_version":1`,
		`"path":"/unchanged-svc"`,
		`"scan_output_hash":"sha256:abc"`,
		`"last_uploaded_execution_id":"exec-1"`,
		`"path":"/removed-svc"`,
		`"package_manager":"npm"`,
		`"scan_output_hash":"sha256:def"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("delta payload missing %q\npayload: %s", want, s)
		}
	}

	// Round-trip: unmarshal back.
	var out Payload
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.PayloadSchemaVersion != CurrentPayloadSchemaVersion {
		t.Errorf("schema version lost: %d", out.PayloadSchemaVersion)
	}
	if len(out.NodeProjectsUnchanged) != 1 || out.NodeProjectsUnchanged[0].Path != "/unchanged-svc" {
		t.Errorf("unchanged ref round-trip lost: %+v", out.NodeProjectsUnchanged)
	}
	if len(out.NodeProjectsRemoved) != 1 || out.NodeProjectsRemoved[0].Path != "/removed-svc" {
		t.Errorf("removed ref round-trip lost: %+v", out.NodeProjectsRemoved)
	}
}
