package codex

import "github.com/step-security/dev-machine-guard/internal/aiagents/event"

// Codex-native hook event names. These are kept in this package and
// NOT promoted to internal/aiagents/event so cross-agent code (policy,
// runtime) cannot branch on them — branching MUST go through
// event.HookPhase instead.
const (
	HookSessionStart      event.HookEvent = "SessionStart"
	HookPreToolUse        event.HookEvent = "PreToolUse"
	HookPermissionRequest event.HookEvent = "PermissionRequest"
	HookPostToolUse       event.HookEvent = "PostToolUse"
	HookUserPromptSubmit  event.HookEvent = "UserPromptSubmit"
	HookStop              event.HookEvent = "Stop"
)

// supportedHookEvents is the install order. Append-only — order is
// significant for install/uninstall reproducibility and shows up in
// user-facing diagnostics.
var supportedHookEvents = []event.HookEvent{
	HookSessionStart,
	HookPreToolUse,
	HookPermissionRequest,
	HookPostToolUse,
	HookUserPromptSubmit,
	HookStop,
}

// SupportedHooks returns a fresh copy of the Codex-supported hook list.
// Callers may freely mutate the returned slice without affecting
// adapter internals.
func (a *Adapter) SupportedHooks() []event.HookEvent {
	out := make([]event.HookEvent, len(supportedHookEvents))
	copy(out, supportedHookEvents)
	return out
}

// phaseFor maps a Codex native hook event onto the normalized hook
// phase. Cross-agent consumers (policy, filtering) branch on phase;
// adapter-specific consumers may still inspect HookEvent.
func phaseFor(h event.HookEvent) event.HookPhase {
	switch h {
	case HookSessionStart:
		return event.HookPhaseSessionStart
	case HookPreToolUse:
		return event.HookPhasePreTool
	case HookPermissionRequest:
		return event.HookPhasePermissionRequest
	case HookPostToolUse:
		return event.HookPhasePostTool
	case HookUserPromptSubmit:
		return event.HookPhaseUserPrompt
	case HookStop:
		return event.HookPhaseStop
	}
	return event.HookPhaseUnknown
}
