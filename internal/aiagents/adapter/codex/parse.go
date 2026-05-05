package codex

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
)

// ParseEvent normalizes a Codex hook stdin payload into a DMG event.
// The raw payload is REDACTED before being attached to the result;
// the original bytes never appear in the returned event.
func (a *Adapter) ParseEvent(ctx context.Context, hookType event.HookEvent, raw []byte) (*event.Event, error) {
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, fmt.Errorf("codex parse: %w", err)
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

	ev.SessionID = stringField(generic, "session_id")
	ev.WorkingDirectory = stringField(generic, "cwd")
	ev.PermissionMode = stringField(generic, "permission_mode")
	ev.ToolName = stringField(generic, "tool_name")
	ev.ToolUseID = stringField(generic, "tool_use_id")

	// Cross-check: the CLI arg names which hook command Codex
	// invoked. On disagreement, keep runtime behavior tied to that
	// hook and record the payload mismatch for audit. The payload
	// claim is not persisted as a field of its own — ev.HookEvent is
	// the single source of truth.
	if claimed := stringField(generic, "hook_event_name"); claimed != "" && claimed != string(hookType) {
		ev.Errors = append(ev.Errors, event.ErrorInfo{
			Stage:   "parse",
			Code:    "hook_event_name_mismatch",
			Message: "cli arg=" + string(hookType) + " payload=" + claimed,
		})
	}

	ev.ActionType = inferActionType(ev.HookEvent, ev.ToolName)

	// Codex has no separate documented failure hook; PostToolUse
	// means the tool completed. Treat it as success unless future
	// Codex versions expose a richer status field.
	if ev.HookPhase == event.HookPhasePostTool {
		ev.ResultStatus = event.ResultSuccess
	}

	cleaned := scrubPayload(generic)
	if v, ok := redact.Value(cleaned).(map[string]any); ok {
		ev.Payload = v
	} else {
		ev.Payload = cleaned
	}

	ev.IsSensitive = isSensitivePayload(generic)

	return ev, nil
}

// scrubPayload swaps bulky / sensitive fields for presence markers
// but preserves audit-evidence fields (prompt, transcript_path,
// source).
func scrubPayload(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		switch strings.ToLower(k) {
		case "transcript", "messages", "stdout", "stderr", "content":
			out[k+"_present"] = true
		case "last_assistant_message":
			out["last_assistant_message_present"] = true
		default:
			out[k] = v
		}
	}
	return out
}

// inferActionType is only meaningful for PreToolUse and PostToolUse.
// PermissionRequest, SessionStart, UserPromptSubmit, and Stop leave
// the field empty — the hook_event field already names the lifecycle
// phase, and permission events describe a decision around a tool call
// rather than a tool call itself.
func inferActionType(hookEvent event.HookEvent, toolName string) event.ActionType {
	switch hookEvent {
	case HookPreToolUse, HookPostToolUse:
	default:
		return ""
	}
	switch {
	case toolName == "Bash":
		return event.ActionCommandExec
	case toolName == "apply_patch":
		return event.ActionFileWrite
	case strings.HasPrefix(toolName, "mcp__"):
		return event.ActionMCPInvocation
	case toolName == "":
		return ""
	default:
		return event.ActionToolUse
	}
}

// ShellCommand extracts the redacted shell command from a parsed
// Codex event. Returns ok=false for everything except `Bash`.
// apply_patch's tool_input.command is a patch payload, not shell
// input.
func (a *Adapter) ShellCommand(ev *event.Event) (cmd string, cwd string, ok bool) {
	if ev == nil || ev.Payload == nil {
		return "", "", false
	}
	if ev.ToolName != "Bash" {
		return "", ev.WorkingDirectory, false
	}
	ti, _ := ev.Payload["tool_input"].(map[string]any)
	if ti == nil {
		return "", ev.WorkingDirectory, false
	}
	c, _ := ti["command"].(string)
	if c == "" {
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
