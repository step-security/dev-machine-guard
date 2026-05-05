package hook

import (
	"context"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/policy"
)

// shouldEvaluatePolicy is the cheap filter that runs before any I/O.
// It is normalized over hook_phase so future agents reuse it without
// branching on Claude-specific hook names.
func shouldEvaluatePolicy(ev *event.Event, cmd string) bool {
	if ev == nil {
		return false
	}
	if ev.HookPhase != event.HookPhasePreTool {
		return false
	}
	if ev.ActionType != event.ActionCommandExec {
		return false
	}
	return cmd != ""
}

// evaluatePolicy is the stage between enrichment and upload. It returns
// (nil, AllowDecision) when the observed binary does not belong to a
// known ecosystem, when the ecosystem block is disabled, when the command
// is not policy-relevant, or when any internal step fails — fail-open is
// preserved on every error path.
//
// The returned adapter.Decision is the *effective* response. The
// evaluator forces ModeAudit before consulting the verdict, so block
// decisions never escape this function. The block code path remains
// exercised by tests that inject a Policy with Mode=block; production
// builds never set it.
func (rt *Runtime) evaluatePolicy(_ context.Context, ev *event.Event, cmd string) (*event.PolicyDecisionInfo, adapter.Decision) {
	allow := adapter.AllowDecision()

	if cmd == "" {
		return nil, allow
	}

	pol := policy.Builtin()
	if rt.Policy != nil {
		pol = *rt.Policy
	}

	parsed := policy.ParseShell(cmd)
	eco := policy.EcosystemFor(parsed.Binary)
	if eco == "" {
		return nil, allow
	}
	if block, ok := pol.Ecosystems[eco]; !ok || !block.Enabled {
		return nil, allow
	}

	req := policy.Request{
		Ecosystem:      eco,
		PackageManager: normalizePM(parsed.Binary),
		CommandKind:    commandKindFor(parsed, ev),
		RegistryFlag:   parsed.RegistryFlag,
		UserconfigFlag: parsed.UserconfigFlag,
		InlineEnv:      parsed.InlineEnv,
	}
	if parsed.ConfigOp != "" {
		req.ConfigKeyMutated = parsed.ConfigKey
		req.ConfigValue = parsed.ConfigValue
	}

	if ev.Enrichments != nil && ev.Enrichments.PackageManager != nil {
		req.Registry = ev.Enrichments.PackageManager.Registry
	}

	verdict := policy.Eval(pol, req)
	mode := policy.ResolveMode(pol)
	wouldBlock := !verdict.Allow
	enforced := wouldBlock && mode == policy.ModeBlock

	info := &event.PolicyDecisionInfo{
		Mode:           string(mode),
		Allowed:        !enforced,
		WouldBlock:     wouldBlock,
		Enforced:       enforced,
		Code:           string(verdict.Code),
		InternalDetail: verdict.InternalDetail,
		Registry:       req.Registry,
		AllowlistHit:   verdict.Allow && req.Registry != "",
		Bypass:         bypassFor(verdict.Code),
	}
	if enforced {
		return info, adapter.Decision{Allow: false, UserMessage: verdict.UserMessage}
	}
	return info, allow
}

// commandKindFor maps a parsed-shell shape onto the policy.Request kind
// vocabulary. Config ops win because the parser detects them with high
// specificity; otherwise we fall back to whatever npm.Enrich classified.
func commandKindFor(parsed policy.ParsedCommand, ev *event.Event) string {
	switch parsed.ConfigOp {
	case "set":
		return "config_set"
	case "delete":
		return "config_delete"
	case "edit":
		return "config_edit"
	}
	if ev.Enrichments != nil && ev.Enrichments.PackageManager != nil {
		if k := ev.Enrichments.PackageManager.CommandKind; k != "" {
			return k
		}
	}
	return "other"
}

// normalizePM collapses execution-only siblings onto their config-owning
// counterpart so managed-key lookups in policy.Eval find the right table.
// `npx` does not own configuration; `npm` does.
func normalizePM(bin string) string {
	switch bin {
	case "npx":
		return "npm"
	case "pnpx":
		return "pnpm"
	case "bunx":
		return "bun"
	}
	return bin
}

// bypassFor maps a policy decision code onto the audit-only Bypass tag.
// Returns "" for non-bypass codes (allow, missing data, etc).
func bypassFor(code policy.DecisionCode) string {
	switch code {
	case policy.CodeRegistryFlag:
		return "registry_flag"
	case policy.CodeRegistryEnv:
		return "env_var"
	case policy.CodeUserconfigFlag:
		return "userconfig_flag"
	case policy.CodeManagedKeyMutation:
		return "config_set"
	case policy.CodeManagedKeyEdit:
		return "config_edit"
	}
	return ""
}
