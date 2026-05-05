package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestRunHook_FailOpenContract asserts the fail-open contract on every
// ERROR path: exit 0, empty stdout, empty stderr. These cases MUST keep
// passing as the stub grows into the real runtime in ticket 2.8 — adding
// parsing, stdin handling, policy evaluation, and upload paths must not
// introduce any non-zero exit or any stderr noise on these inputs.
//
// Valid calls (well-formed agent + event) are deliberately excluded:
// they're a different contract — exit 0 + a valid agent-allow JSON body
// on stdout — and belong in a separate wire-format test added with 2.8.
func TestRunHook_FailOpenContract(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"no args", nil},
		{"only agent", []string{"claude-code"}},
		{"only agent (codex)", []string{"codex"}},
		{"unsupported agent", []string{"windsurf", "PreToolUse"}},
		{"empty agent", []string{"", "PreToolUse"}},
		{"empty event", []string{"claude-code", ""}},
		{"trailing extras", []string{"claude-code", "PreToolUse", "extra", "args"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			rc := RunHook(bytes.NewReader(nil), &stdout, &stderr, tc.args)
			if rc != 0 {
				t.Errorf("expected exit 0 (fail-open contract), got %d", rc)
			}
			if stdout.Len() != 0 {
				t.Errorf("expected empty stdout on error path, got %q", stdout.String())
			}
			if stderr.Len() != 0 {
				t.Errorf("expected empty stderr on error path, got %q", stderr.String())
			}
		})
	}
}

// TestRunHook_ValidPayloadEmitsAllow exercises the wire-format contract
// for well-formed inputs: a recognized agent + event with a parseable
// payload returns exit 0 and emits a valid JSON allow response on stdout.
// This pins the success path that the fail-open test deliberately
// excludes.
func TestRunHook_ValidPayloadEmitsAllow(t *testing.T) {
	cases := []struct {
		name      string
		agent     string
		hookEvent string
		payload   string
		// expectAllowKey is "continue" for Claude (non-empty allow body)
		// and "" for Codex (allow body is the empty object {}).
		expectAllowKey string
	}{
		{
			name:           "claude-code PreToolUse Bash",
			agent:          "claude-code",
			hookEvent:      "PreToolUse",
			payload:        `{"tool_name":"Bash","tool_input":{"command":"ls"}}`,
			expectAllowKey: "continue",
		},
		{
			name:           "codex PreToolUse Bash",
			agent:          "codex",
			hookEvent:      "PreToolUse",
			payload:        `{"tool_name":"Bash","tool_input":{"command":"ls"}}`,
			expectAllowKey: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			rc := RunHook(strings.NewReader(tc.payload), &stdout, &stderr, []string{tc.agent, tc.hookEvent})
			if rc != 0 {
				t.Errorf("expected exit 0, got %d", rc)
			}
			if stderr.Len() != 0 {
				t.Errorf("expected empty stderr, got %q", stderr.String())
			}
			body := bytes.TrimSpace(stdout.Bytes())
			var resp map[string]any
			if err := json.Unmarshal(body, &resp); err != nil {
				t.Fatalf("stdout not valid JSON: %v: %q", err, body)
			}
			if tc.expectAllowKey != "" && resp[tc.expectAllowKey] != true {
				t.Errorf("expected %q=true in allow response, got %v", tc.expectAllowKey, resp)
			}
			if tc.expectAllowKey == "" && len(resp) != 0 {
				t.Errorf("expected empty-object allow response, got %v", resp)
			}
		})
	}
}
