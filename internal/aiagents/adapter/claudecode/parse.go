package claudecode

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
)

// ParseEvent normalizes a Claude Code hook stdin payload into an event.
// The raw payload is REDACTED before being attached to the result; the
// original bytes never appear in the returned event.
func (a *Adapter) ParseEvent(ctx context.Context, hookType event.HookEvent, raw []byte) (*event.Event, error) {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("claudecode parse: %w", err)
	}
	if generic == nil {
		generic = map[string]any{}
	}

	ev := &event.Event{
		SchemaVersion: event.SchemaVersion,
		EventID:       event.NewEventID(),
		Timestamp:     time.Now().UTC(),
		AgentName:     AgentName,
		HookEvent:     hookType,
		HookPhase:     phaseFor(hookType),
		ResultStatus:  event.ResultObserved,
	}

	// Spec-documented fields only. Names match
	// https://code.claude.com/docs/en/hooks.md verbatim.
	ev.SessionID = stringField(generic, "session_id")
	ev.WorkingDirectory = stringField(generic, "cwd")
	ev.ToolName = stringField(generic, "tool_name")
	ev.ToolUseID = stringField(generic, "tool_use_id")
	ev.PermissionMode = stringField(generic, "permission_mode")

	// Cross-check: the CLI arg names which hook command Claude invoked.
	// On disagreement, keep runtime behavior tied to that hook and record
	// the payload mismatch for audit. The payload claim is not persisted
	// as a field of its own — ev.HookEvent is the single source of truth,
	// and the mismatch annotation captures the disagreement.
	if claimed := stringField(generic, "hook_event_name"); claimed != "" && claimed != string(hookType) {
		ev.Errors = append(ev.Errors, event.ErrorInfo{
			Stage:   "parse",
			Code:    "hook_event_name_mismatch",
			Message: "cli arg=" + string(hookType) + " payload=" + claimed,
		})
	}

	ev.ActionType = inferActionType(ev.HookEvent, ev.ToolName, generic)

	// PostToolUseFailure means the tool already failed; record the
	// canonical error status so downstream readers don't have to peek
	// inside the payload to learn the outcome.
	if ev.HookEvent == event.HookPostToolUseFailure {
		ev.ResultStatus = event.ResultError
	}

	// Attach a redacted view of the payload. Drop high-volume transcript
	// fields by default — they may be re-attached later by an enrichment.
	cleaned := scrubPayload(generic)
	ev.Payload = redact.Value(cleaned).(map[string]any)

	ev.IsSensitive = isSensitivePayload(generic)

	return ev, nil
}

// scrubPayload removes payload fields whose values are either too bulky
// to embed in a record or too unstructured for the key-based redactor
// to handle safely:
//
//   - transcript / messages: full chat history; can be many MB.
//   - stdout / stderr: tool output; potentially huge and noisy.
//   - content: ElicitationResult form-response field. Form values are
//     user-defined and may carry OTPs, credentials, or other secrets
//     under arbitrary key names the general redactor will not catch.
//
// Each is replaced with a `<key>_present: true` marker. The user's
// prompt (UserPromptSubmit.payload.prompt) is deliberately NOT scrubbed:
// it IS the audit evidence for that hook event, and the standard
// redactor still walks the value to scrub any secrets pasted into it.
func scrubPayload(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		switch strings.ToLower(k) {
		case "transcript", "messages", "stdout", "stderr", "content":
			out[k+"_present"] = true
		case "transcript_path":
			// Path is fine; full transcript scanning happens via the secret
			// scanner enrichment with bounded reads.
			out[k] = v
		default:
			out[k] = v
		}
	}
	return out
}

// inferActionType classifies the operation a tool-bearing hook is about
// to perform (PreToolUse) or just performed (PostToolUse,
// PostToolUseFailure). Lifecycle hooks (SessionStart, SessionEnd,
// Notification, Stop, SubagentStop, UserPromptSubmit) return "" — the
// hook_event field already names the lifecycle phase, so action_type
// is omitted in those records.
func inferActionType(hookEvent event.HookEvent, toolName string, p map[string]any) event.ActionType {
	switch hookEvent {
	case event.HookPreToolUse, event.HookPostToolUse, event.HookPostToolUseFailure:
		// fall through to tool-name routing
	default:
		return ""
	}
	switch strings.ToLower(toolName) {
	case "bash", "shell":
		return event.ActionCommandExec
	case "read":
		return event.ActionFileRead
	case "write", "edit", "multiedit":
		return event.ActionFileWrite
	case "webfetch", "websearch", "http":
		return event.ActionNetworkRequest
	case "":
		// Some hook payloads carry the command nested under tool_input.
		if hasShellCommand(p) {
			return event.ActionCommandExec
		}
		return ""
	default:
		if strings.HasPrefix(strings.ToLower(toolName), "mcp__") {
			return event.ActionMCPInvocation
		}
		return event.ActionToolUse
	}
}

func hasShellCommand(p map[string]any) bool {
	ti, ok := p["tool_input"].(map[string]any)
	if !ok {
		return false
	}
	if _, ok := ti["command"].(string); ok {
		return true
	}
	return false
}

// ShellCommand extracts the redacted shell command from a Claude Code
// hook payload, if any. Returns the empty string when no shell command
// is present. The result has already been redacted.
func (a *Adapter) ShellCommand(ev *event.Event) (cmd string, cwd string, ok bool) {
	if ev == nil || ev.Payload == nil {
		return "", "", false
	}
	ti, ok := ev.Payload["tool_input"].(map[string]any)
	if !ok {
		return "", ev.WorkingDirectory, false
	}
	c, ok := ti["command"].(string)
	if !ok || c == "" {
		return "", ev.WorkingDirectory, false
	}
	wd, _ := ti["cwd"].(string)
	if wd == "" {
		wd = ev.WorkingDirectory
	}
	return c, wd, true
}

func isSensitivePayload(p map[string]any) bool {
	ti, ok := p["tool_input"].(map[string]any)
	if !ok {
		return false
	}
	for _, key := range []string{"file_path", "path", "filename"} {
		if v, ok := ti[key].(string); ok && redact.IsSensitivePath(v) {
			return true
		}
	}
	return false
}

func stringField(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

// phaseFor maps a Claude Code native hook event onto the normalized
// hook phase. Cross-agent consumers (policy, filtering) branch on
// phase; agent-specific consumers may still inspect HookEvent.
func phaseFor(h event.HookEvent) event.HookPhase {
	switch h {
	case event.HookPreToolUse:
		return event.HookPhasePreTool
	case event.HookPostToolUse:
		return event.HookPhasePostTool
	case event.HookPostToolUseFailure:
		return event.HookPhasePostToolFailure
	case event.HookPermissionRequest:
		return event.HookPhasePermissionRequest
	case event.HookPermissionDenied:
		return event.HookPhasePermissionDenied
	case event.HookElicitation:
		return event.HookPhaseElicitation
	case event.HookElicitationResult:
		return event.HookPhaseElicitationResult
	case event.HookUserPrompt:
		return event.HookPhaseUserPrompt
	case event.HookSessionStart:
		return event.HookPhaseSessionStart
	case event.HookSessionEnd:
		return event.HookPhaseSessionEnd
	case event.HookNotification:
		return event.HookPhaseNotification
	case event.HookStop:
		return event.HookPhaseStop
	case event.HookSubagentStop:
		return event.HookPhaseSubagentStop
	}
	return event.HookPhaseUnknown
}
