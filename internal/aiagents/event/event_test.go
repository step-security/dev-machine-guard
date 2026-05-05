package event_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

func TestSchemaVersionIsDMGHookEventV1(t *testing.T) {
	// schema_version is "dmg.hook.event/v1". The backend strict-matches;
	// bumping requires a coordinated change.
	if event.SchemaVersion != "dmg.hook.event/v1" {
		t.Errorf("SchemaVersion = %q, want dmg.hook.event/v1", event.SchemaVersion)
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
		`"schema_version":"dmg.hook.event/v1"`,
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

func TestEnumWireValues(t *testing.T) {
	// Every enum string is part of the wire format. The backend
	// strict-matches; renaming a constant is a coordinated migration,
	// not a refactor. This test pins the literals so a casual rename
	// fails CI loudly rather than silently breaking telemetry.
	cases := map[string]string{
		// ActionType
		"ActionFileRead":       string(event.ActionFileRead),
		"ActionFileWrite":      string(event.ActionFileWrite),
		"ActionFileDelete":     string(event.ActionFileDelete),
		"ActionCommandExec":    string(event.ActionCommandExec),
		"ActionNetworkRequest": string(event.ActionNetworkRequest),
		"ActionToolUse":        string(event.ActionToolUse),
		"ActionMCPInvocation":  string(event.ActionMCPInvocation),
		// ResultStatus
		"ResultObserved": string(event.ResultObserved),
		"ResultSuccess":  string(event.ResultSuccess),
		"ResultError":    string(event.ResultError),
		"ResultTimeout":  string(event.ResultTimeout),
		"ResultPartial":  string(event.ResultPartial),
		// HookEvent (Claude Code natives)
		"HookPreToolUse":         string(event.HookPreToolUse),
		"HookPostToolUse":        string(event.HookPostToolUse),
		"HookPostToolUseFailure": string(event.HookPostToolUseFailure),
		"HookSessionStart":       string(event.HookSessionStart),
		"HookSessionEnd":         string(event.HookSessionEnd),
		"HookNotification":       string(event.HookNotification),
		"HookStop":               string(event.HookStop),
		"HookSubagentStop":       string(event.HookSubagentStop),
		"HookUserPrompt":         string(event.HookUserPrompt),
		"HookElicitation":        string(event.HookElicitation),
		"HookElicitationResult":  string(event.HookElicitationResult),
		"HookPermissionRequest":  string(event.HookPermissionRequest),
		"HookPermissionDenied":   string(event.HookPermissionDenied),
		// HookPhase
		"HookPhaseUnknown":           string(event.HookPhaseUnknown),
		"HookPhasePreTool":           string(event.HookPhasePreTool),
		"HookPhasePostTool":          string(event.HookPhasePostTool),
		"HookPhasePostToolFailure":   string(event.HookPhasePostToolFailure),
		"HookPhasePermissionRequest": string(event.HookPhasePermissionRequest),
		"HookPhasePermissionDenied":  string(event.HookPhasePermissionDenied),
		"HookPhaseElicitation":       string(event.HookPhaseElicitation),
		"HookPhaseElicitationResult": string(event.HookPhaseElicitationResult),
		"HookPhaseUserPrompt":        string(event.HookPhaseUserPrompt),
		"HookPhaseSessionStart":      string(event.HookPhaseSessionStart),
		"HookPhaseSessionEnd":        string(event.HookPhaseSessionEnd),
		"HookPhaseNotification":      string(event.HookPhaseNotification),
		"HookPhaseStop":              string(event.HookPhaseStop),
		"HookPhaseSubagentStop":      string(event.HookPhaseSubagentStop),
	}
	want := map[string]string{
		"ActionFileRead":             "file_read",
		"ActionFileWrite":            "file_write",
		"ActionFileDelete":           "file_delete",
		"ActionCommandExec":          "command_exec",
		"ActionNetworkRequest":       "network_request",
		"ActionToolUse":              "tool_use",
		"ActionMCPInvocation":        "mcp_invocation",
		"ResultObserved":             "observed",
		"ResultSuccess":              "success",
		"ResultError":                "error",
		"ResultTimeout":              "timeout",
		"ResultPartial":              "partial",
		"HookPreToolUse":             "PreToolUse",
		"HookPostToolUse":            "PostToolUse",
		"HookPostToolUseFailure":     "PostToolUseFailure",
		"HookSessionStart":           "SessionStart",
		"HookSessionEnd":             "SessionEnd",
		"HookNotification":           "Notification",
		"HookStop":                   "Stop",
		"HookSubagentStop":           "SubagentStop",
		"HookUserPrompt":             "UserPromptSubmit",
		"HookElicitation":            "Elicitation",
		"HookElicitationResult":      "ElicitationResult",
		"HookPermissionRequest":      "PermissionRequest",
		"HookPermissionDenied":       "PermissionDenied",
		"HookPhaseUnknown":           "unknown",
		"HookPhasePreTool":           "pre_tool",
		"HookPhasePostTool":          "post_tool",
		"HookPhasePostToolFailure":   "post_tool_failure",
		"HookPhasePermissionRequest": "permission_request",
		"HookPhasePermissionDenied":  "permission_denied",
		"HookPhaseElicitation":       "elicitation",
		"HookPhaseElicitationResult": "elicitation_result",
		"HookPhaseUserPrompt":        "user_prompt",
		"HookPhaseSessionStart":      "session_start",
		"HookPhaseSessionEnd":        "session_end",
		"HookPhaseNotification":      "notification",
		"HookPhaseStop":              "stop",
		"HookPhaseSubagentStop":      "subagent_stop",
	}
	for name, got := range cases {
		if got != want[name] {
			t.Errorf("%s wire value = %q, want %q", name, got, want[name])
		}
	}
}

func TestEventFullRoundTrip(t *testing.T) {
	// Schema-drift detector: populate every field, marshal, unmarshal,
	// reflect.DeepEqual. If anyone adds a field without giving it
	// (de)serialization coverage on both sides, this fails.
	in := &event.Event{
		SchemaVersion:    event.SchemaVersion,
		EventID:          "deadbeef",
		Timestamp:        time.Date(2026, 5, 5, 12, 0, 0, 123456789, time.UTC),
		AgentName:        "claude-code",
		AgentVersion:     "1.2.3",
		HookEvent:        event.HookPreToolUse,
		HookPhase:        event.HookPhasePreTool,
		SessionID:        "sess-1",
		WorkingDirectory: "/tmp/work",
		PermissionMode:   "default",
		CustomerID:       "cust-1",
		UserIdentity:     "alice@example.com",
		DeviceID:         "dev-1",
		ActionType:       event.ActionCommandExec,
		ToolName:         "Bash",
		ToolUseID:        "use-1",
		ResultStatus:     event.ResultObserved,
		IsSensitive:      true,
		Payload:          map[string]any{"k": "v"},
		Classifications: &event.Classifications{
			IsShellCommand:    true,
			IsPackageManager:  true,
			IsMCPRelated:      true,
			IsFileOperation:   true,
			IsNetworkActivity: true,
		},
		Enrichments: &event.Enrichments{
			Shell: &event.ShellEnrichment{
				Command:          "echo hi",
				CommandTruncated: false,
				WorkingDirectory: "/tmp",
			},
			PackageManager: &event.PackageManagerInfo{
				Detected:        true,
				Name:            "npm",
				CommandKind:     "install",
				Registry:        "https://registry.npmjs.org",
				ConfigSources:   []string{".npmrc"},
				PackagesAdded:   []event.PackageRef{{Name: "foo", Version: "1.0.0"}},
				PackagesRemoved: []event.PackageRef{{Name: "bar"}},
				PackagesChanged: []event.PackageRef{{Name: "baz", Version: "2.0.0"}},
				Confidence:      "high",
				Evidence:        []string{"package.json"},
			},
			MCP: &event.MCPInfo{
				Kind:          "local",
				ServerName:    "server-foo",
				ServerCommand: "npx -y @modelcontextprotocol/server-foo",
			},
			Secrets: &event.SecretsScanInfo{
				Scanned:   true,
				FilesSeen: 3,
				BytesSeen: 1024,
				Findings: []event.SecretFinding{{
					RuleID:        "aws-key",
					FilePath:      "/tmp/x",
					LineStart:     1,
					LineEnd:       1,
					Fingerprint:   "abc",
					MaskedPreview: "AKIA…",
					Confidence:    "high",
				}},
				TimedOut: false,
			},
		},
		Timeouts: []event.TimeoutInfo{{
			Stage:   "enrich",
			Cap:     5 * time.Second,
			Elapsed: 6 * time.Second,
		}},
		Errors: []event.ErrorInfo{{
			Stage:   "redact",
			Code:    "regex_overflow",
			Message: "pattern too long",
		}},
		PolicyDecision: &event.PolicyDecisionInfo{
			Mode:           "audit",
			Allowed:        true,
			WouldBlock:     true,
			Enforced:       false,
			Code:           "blocked_pkg",
			InternalDetail: "matched rule X",
			Registry:       "npm",
			AllowlistHit:   false,
			Bypass:         "registry_flag",
		},
	}
	out, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var got event.Event
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, &got) {
		t.Errorf("round-trip mismatch.\n in = %+v\nout = %+v", in, &got)
	}
}

func TestPackageManagerInfo_AlwaysEmitsDetected(t *testing.T) {
	// PackageManagerInfo.Detected has no omitempty by design — even a
	// negative detection ("we ran the package-manager classifier; nothing
	// matched") is meaningful to downstream pipelines. Guard the absence
	// of omitempty.
	out, err := json.Marshal(event.PackageManagerInfo{Detected: false})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"detected":false`) {
		t.Errorf("expected detected:false to appear in %s", string(out))
	}
}

func TestSecretsScanInfo_AlwaysEmitsCounters(t *testing.T) {
	// Scanned/FilesSeen/BytesSeen have no omitempty — a session-end with
	// zero files seen is still a meaningful "we scanned and found nothing"
	// signal. Guard the absence of omitempty.
	out, err := json.Marshal(event.SecretsScanInfo{})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{`"scanned":false`, `"files_seen":0`, `"bytes_seen":0`} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %s in %s", want, got)
		}
	}
}

func TestPolicyDecisionInfo_AlwaysEmitsAllowedAndAllowlistHit(t *testing.T) {
	// Allowed and AllowlistHit have no omitempty: every policy decision
	// must answer both questions explicitly, even when both are false.
	out, err := json.Marshal(event.PolicyDecisionInfo{})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{`"allowed":false`, `"allowlist_hit":false`} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %s in %s", want, got)
		}
	}
}

func TestEnrichments_NilSubBlocksOmitted(t *testing.T) {
	// All Enrichments sub-fields are pointers with omitempty — a top-level
	// Enrichments with no sub-blocks should marshal to {}, not to a struct
	// with `null` keys.
	out, err := json.Marshal(event.Enrichments{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "{}" {
		t.Errorf("empty Enrichments should marshal to {}, got %s", string(out))
	}
}

func TestPolicyBypassValues_RoundTrip(t *testing.T) {
	// The five documented bypass tags must round-trip as plain strings.
	// They are part of the audit wire format.
	for _, tag := range []string{"registry_flag", "env_var", "config_set", "config_edit", "userconfig_flag"} {
		t.Run(tag, func(t *testing.T) {
			in := event.PolicyDecisionInfo{Bypass: tag}
			out, err := json.Marshal(in)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(out), `"bypass":"`+tag+`"`) {
				t.Errorf("bypass %q missing from %s", tag, string(out))
			}
			var back event.PolicyDecisionInfo
			if err := json.Unmarshal(out, &back); err != nil {
				t.Fatal(err)
			}
			if back.Bypass != tag {
				t.Errorf("round-trip lost bypass tag: got %q want %q", back.Bypass, tag)
			}
		})
	}
}

func TestTimestampIsRFC3339Nano(t *testing.T) {
	// Backend parses timestamp as RFC3339Nano (Go's default time.Time
	// marshal). Pin it so a switch to a custom MarshalJSON would fail
	// the test.
	ev := event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       "x",
		Timestamp:     time.Date(2026, 5, 5, 12, 0, 0, 123456789, time.UTC),
		AgentName:     "claude-code",
		HookEvent:     event.HookPreToolUse,
		ResultStatus:  event.ResultObserved,
	}
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	want := `"timestamp":"2026-05-05T12:00:00.123456789Z"`
	if !strings.Contains(string(out), want) {
		t.Errorf("expected %s in %s", want, string(out))
	}
}

func TestPolicyDecisionInfoTruthTable(t *testing.T) {
	// Verify the truth-table documented on PolicyDecisionInfo round-trips
	// through JSON cleanly. Only audit rows are emitted in production;
	// the block row is exercised by tests so block-mode flip is a flag
	// flip, not a shape change.
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
