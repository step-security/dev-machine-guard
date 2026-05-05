package event_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

func TestSchemaVersionIsAIAgentV1(t *testing.T) {
	// Plan §1.11: schema_version is "ai_agent.event/v1". The backend
	// strict-matches; bumping requires a coordinated change.
	if event.SchemaVersion != "ai_agent.event/v1" {
		t.Errorf("SchemaVersion = %q, want ai_agent.event/v1", event.SchemaVersion)
	}
}

func TestNewEventIDIs128BitHex(t *testing.T) {
	id := event.NewEventID()
	if len(id) != 32 {
		t.Errorf("NewEventID len = %d, want 32 (16 bytes hex)", len(id))
	}
	for _, c := range id {
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !ok {
			t.Errorf("NewEventID contains non-hex byte %q in %q", c, id)
			break
		}
	}
}

func TestNewEventIDIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1024)
	for i := range 1024 {
		id := event.NewEventID()
		if _, dup := seen[id]; dup {
			t.Fatalf("NewEventID collision after %d draws: %s", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestEventJSONOmitsEmptyFields(t *testing.T) {
	ev := &event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       "abcd",
		Timestamp:     time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
		AgentName:     "claude-code",
		HookEvent:     event.HookPreToolUse,
		ResultStatus:  event.ResultObserved,
	}
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	// Optional fields must be elided.
	for _, banned := range []string{
		"agent_version", "session_id", "permission_mode", "customer_id",
		"user_identity", "device_id", "action_type", "tool_name",
		"tool_use_id", "is_sensitive", "payload", "classifications",
		"enrichments", "timeouts", "errors", "policy_decision",
	} {
		if strings.Contains(got, `"`+banned+`"`) {
			t.Errorf("expected %q to be omitted from empty event, got %s", banned, got)
		}
	}
	// schema_version, event_id, agent_name, hook_event, result_status
	// are always present.
	for _, want := range []string{
		`"schema_version":"ai_agent.event/v1"`,
		`"event_id":"abcd"`,
		`"agent_name":"claude-code"`,
		`"hook_event":"PreToolUse"`,
		`"result_status":"observed"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected output to contain %s, got %s", want, got)
		}
	}
}

func TestClassificationsIsZero(t *testing.T) {
	var c event.Classifications
	if !c.IsZero() {
		t.Error("zero Classifications should report IsZero=true")
	}
	c.IsShellCommand = true
	if c.IsZero() {
		t.Error("non-zero Classifications should report IsZero=false")
	}
}

func TestPolicyDecisionInfoTruthTable(t *testing.T) {
	// Verify the truth-table documented on PolicyDecisionInfo round-trips
	// through JSON cleanly. Phase 1 only emits the audit rows; the block
	// row is exercised by tests so block-mode flip is a flag flip, not a
	// shape change.
	cases := []struct {
		name string
		info event.PolicyDecisionInfo
		want []string // substrings that must appear
	}{
		{
			name: "audit no violation",
			info: event.PolicyDecisionInfo{Mode: "audit", Allowed: true},
			want: []string{`"mode":"audit"`, `"allowed":true`},
		},
		{
			name: "audit violation",
			info: event.PolicyDecisionInfo{Mode: "audit", Allowed: true, WouldBlock: true},
			want: []string{`"would_block":true`, `"allowed":true`},
		},
		{
			name: "block violation",
			info: event.PolicyDecisionInfo{Mode: "block", Allowed: false, WouldBlock: true, Enforced: true},
			want: []string{`"allowed":false`, `"enforced":true`, `"would_block":true`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := json.Marshal(tc.info)
			if err != nil {
				t.Fatal(err)
			}
			got := string(out)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %s in %s", w, got)
				}
			}
		})
	}
}
