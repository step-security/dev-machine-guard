package telemetry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// TestPayload_WSL_WireContract locks the enterprise wire shape the agent-api
// backend (ddbmodels.DeviceTelemetry.WSL) unmarshals: a top-level "wsl" object
// with the agreed keys. If these tags drift, backend ingestion silently drops
// the block.
func TestPayload_WSL_WireContract(t *testing.T) {
	running := true
	defaultUID := uint32(1000)
	p := &Payload{
		CustomerID: "c", DeviceID: "d",
		WSL: &model.WSLInfo{
			Presence:  model.WSLPresenceYes,
			Installed: true,
			Active:    true,
			Version:   "2.7.11.0",
			Distros: []model.WSLDistro{{
				Name: "Ubuntu-24.04", DistroID: "{45fef9ed-8681-454f-a4ae-78b3ad117616}",
				WSLVersion: 2, Running: running,
				Default: true, OwnerSID: "S-1-5-21-x-500",
				BasePath:   `C:\Users\a\AppData\Local\wsl\{g}`,
				DefaultUID: &defaultUID,
			}},
		},
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	for _, want := range []string{
		`"wsl":`, `"presence":"yes"`, `"installed":true`, `"active":true`,
		`"version":"2.7.11.0"`, `"distros":`, `"name":"Ubuntu-24.04"`,
		`"wsl_version":2`, `"running":true`, `"default":true`,
		`"owner_sid":"S-1-5-21-x-500"`, `"base_path":`,
		// The guest-identity pair: distro_id is the correlation key, default_uid
		// tells the backend whether the distro even has a user home to scan.
		`"distro_id":"{45fef9ed-8681-454f-a4ae-78b3ad117616}"`, `"default_uid":1000`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("payload JSON missing %s\ngot: %s", want, s)
		}
	}
}

// TestPayload_WSL_OmittedWhenNil: a non-Windows / gated-off agent must not emit
// a "wsl" key at all (omitempty), so the backend's nil-skip leaves any stored
// value untouched.
func TestPayload_WSL_OmittedWhenNil(t *testing.T) {
	b, err := json.Marshal(&Payload{CustomerID: "c", DeviceID: "d"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"wsl"`) {
		t.Errorf("nil WSL should be omitted, got: %s", b)
	}
}

// TestPayload_WSL_RootUIDSurvivesOmitempty: DefaultUID is a pointer precisely so
// that uid 0 (root-only distro — nothing worth scanning) stays on the wire
// instead of being swallowed by omitempty and read as "unknown".
func TestPayload_WSL_RootUIDSurvivesOmitempty(t *testing.T) {
	zero := uint32(0)
	b, err := json.Marshal(&Payload{
		CustomerID: "c", DeviceID: "d",
		WSL: &model.WSLInfo{
			Presence: model.WSLPresenceYes,
			Distros:  []model.WSLDistro{{Name: "Imported", DefaultUID: &zero}},
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"default_uid":0`) {
		t.Errorf(`expected "default_uid":0 on the wire, got: %s`, b)
	}
}
