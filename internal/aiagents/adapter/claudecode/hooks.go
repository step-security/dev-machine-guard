package claudecode

import "github.com/step-security/dev-machine-guard/internal/aiagents/event"

// supportedHookEvents enumerates the Claude Code hook events DMG wires
// up. Order is significant for install/uninstall reproducibility —
// append, do not insert. This list is the single source of truth for
// what `hooks install --agent claude-code` writes into
// ~/.claude/settings.json.
var supportedHookEvents = []event.HookEvent{
	event.HookPreToolUse,
	event.HookPostToolUse,
	event.HookSessionStart,
	event.HookSessionEnd,
	event.HookUserPrompt,
	event.HookStop,
	event.HookSubagentStop,
	event.HookNotification,
	event.HookPostToolUseFailure,
	event.HookElicitation,
	event.HookElicitationResult,
	event.HookPermissionRequest,
	event.HookPermissionDenied,
}

// SupportedHooks returns a fresh copy of the Claude-supported hook list.
// Callers may freely mutate the returned slice without affecting adapter
// internals.
func (a *Adapter) SupportedHooks() []event.HookEvent {
	out := make([]event.HookEvent, len(supportedHookEvents))
	copy(out, supportedHookEvents)
	return out
}
