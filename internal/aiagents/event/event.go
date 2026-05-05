// Package event defines the canonical AI-agent event schema. Adapters
// produce *Event from agent-piped stdin payloads; the hook runtime
// enriches and emits to telemetry. Every record carries an explicit
// schema_version so downstream consumers can detect format drift.
//
// SchemaVersion is "dmg.hook.event/v1". The constant lives here rather
// than in a separate version package because it is the schema's own
// identity, not a build-info concern.
package event

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// SchemaVersion identifies this event schema on the wire and in
// telemetry. Every Event written or uploaded carries this value in its
// SchemaVersion field. Bumping requires a coordinated backend change.
const SchemaVersion = "dmg.hook.event/v1"

// ActionType enumerates the kinds of activity the runtime can observe.
// It applies only to tool-bearing hook events (PreToolUse, PostToolUse,
// PostToolUseFailure). Lifecycle hooks (SessionStart, SessionEnd,
// Notification, Stop, SubagentStop, UserPromptSubmit, Elicitation,
// ElicitationResult, PermissionRequest, PermissionDenied) leave
// action_type unset — the hook_event field already names the
// lifecycle phase, and permission events describe a decision around a
// tool call rather than a tool call itself.
type ActionType string

const (
	ActionFileRead       ActionType = "file_read"
	ActionFileWrite      ActionType = "file_write"
	ActionFileDelete     ActionType = "file_delete"
	ActionCommandExec    ActionType = "command_exec"
	ActionNetworkRequest ActionType = "network_request"
	ActionToolUse        ActionType = "tool_use"
	ActionMCPInvocation  ActionType = "mcp_invocation"
)

// ResultStatus describes the recorded outcome.
type ResultStatus string

const (
	ResultObserved ResultStatus = "observed"
	ResultSuccess  ResultStatus = "success"
	ResultError    ResultStatus = "error"
	ResultTimeout  ResultStatus = "timeout"
	ResultPartial  ResultStatus = "partial"
)

// HookEvent is the native, agent-owned label for a hook lifecycle event.
// The string value is whatever the originating agent wrote on the wire —
// PreToolUse for Claude Code today, but tool.execute.before or
// pre_run_command for future adapters. It is NOT a global enum of every
// hook the runtime supports; the supported set lives behind each
// adapter's SupportedHooks() method.
//
// Constants below are convenience values for Claude Code, kept here so
// adapter and runtime code can refer to them by name without a separate
// adapter import. New adapters should define their own native constants
// in their own packages rather than adding to this list.
type HookEvent string

const (
	HookPreToolUse         HookEvent = "PreToolUse"
	HookPostToolUse        HookEvent = "PostToolUse"
	HookPostToolUseFailure HookEvent = "PostToolUseFailure"
	HookSessionStart       HookEvent = "SessionStart"
	HookSessionEnd         HookEvent = "SessionEnd"
	HookNotification       HookEvent = "Notification"
	HookStop               HookEvent = "Stop"
	HookSubagentStop       HookEvent = "SubagentStop"
	HookUserPrompt         HookEvent = "UserPromptSubmit"
	HookElicitation        HookEvent = "Elicitation"
	HookElicitationResult  HookEvent = "ElicitationResult"
	HookPermissionRequest  HookEvent = "PermissionRequest"
	HookPermissionDenied   HookEvent = "PermissionDenied"
)

// HookPhase is the normalized lifecycle classification of a hook event,
// independent of the originating agent. Adapters populate this alongside
// the native HookEvent. Policy and other cross-agent consumers should
// branch on HookPhase, never on a native HookEvent value.
type HookPhase string

const (
	HookPhaseUnknown           HookPhase = "unknown"
	HookPhasePreTool           HookPhase = "pre_tool"
	HookPhasePostTool          HookPhase = "post_tool"
	HookPhasePostToolFailure   HookPhase = "post_tool_failure"
	HookPhasePermissionRequest HookPhase = "permission_request"
	HookPhasePermissionDenied  HookPhase = "permission_denied"
	HookPhaseElicitation       HookPhase = "elicitation"
	HookPhaseElicitationResult HookPhase = "elicitation_result"
	HookPhaseUserPrompt        HookPhase = "user_prompt"
	HookPhaseSessionStart      HookPhase = "session_start"
	HookPhaseSessionEnd        HookPhase = "session_end"
	HookPhaseNotification      HookPhase = "notification"
	HookPhaseStop              HookPhase = "stop"
	HookPhaseSubagentStop      HookPhase = "subagent_stop"
)

// Event is the canonical AI-agent event record. JSON keys match the
// upload wire format. Optional fields use omitempty so absent data stays
// out of records.
type Event struct {
	SchemaVersion    string              `json:"schema_version"`
	EventID          string              `json:"event_id"`
	Timestamp        time.Time           `json:"timestamp"`
	AgentName        string              `json:"agent_name"`
	AgentVersion     string              `json:"agent_version,omitempty"`
	HookEvent        HookEvent           `json:"hook_event"`
	HookPhase        HookPhase           `json:"hook_phase,omitempty"`
	SessionID        string              `json:"session_id,omitempty"`
	WorkingDirectory string              `json:"working_directory,omitempty"`
	PermissionMode   string              `json:"permission_mode,omitempty"`
	CustomerID       string              `json:"customer_id,omitempty"`
	UserIdentity     string              `json:"user_identity,omitempty"`
	DeviceID         string              `json:"device_id,omitempty"`
	ActionType       ActionType          `json:"action_type,omitempty"`
	ToolName         string              `json:"tool_name,omitempty"`
	ToolUseID        string              `json:"tool_use_id,omitempty"`
	ResultStatus     ResultStatus        `json:"result_status"`
	IsSensitive      bool                `json:"is_sensitive,omitempty"`
	Payload          map[string]any      `json:"payload,omitempty"`
	Classifications  *Classifications    `json:"classifications,omitempty"`
	Enrichments      *Enrichments        `json:"enrichments,omitempty"`
	Timeouts         []TimeoutInfo       `json:"timeouts,omitempty"`
	Errors           []ErrorInfo         `json:"errors,omitempty"`
	PolicyDecision   *PolicyDecisionInfo `json:"policy_decision,omitempty"`
}

// PolicyDecisionInfo carries the full audit-side detail of a policy
// evaluation. The agent only sees a generic block message; this struct
// is the complete answer to "what did the runtime decide and why" in
// telemetry.
//
// Allowed records what the endpoint actually returned to the agent — it
// is the effective decision, not the policy verdict. WouldBlock captures
// the policy verdict; Enforced records whether the endpoint acted on it.
//
// Truth table:
//
//	mode=audit, no violation → Allowed=true,  WouldBlock=false, Enforced=false
//	mode=audit, violation    → Allowed=true,  WouldBlock=true,  Enforced=false
//	mode=block, no violation → Allowed=true,  WouldBlock=false, Enforced=false
//	mode=block, violation    → Allowed=false, WouldBlock=true,  Enforced=true
//
// dev-machine-guard currently runs audit-only, so Enforced is always
// false on shipped builds.
type PolicyDecisionInfo struct {
	Mode           string `json:"mode,omitempty"` // audit | block
	Allowed        bool   `json:"allowed"`
	WouldBlock     bool   `json:"would_block,omitempty"`
	Enforced       bool   `json:"enforced,omitempty"`
	Code           string `json:"code,omitempty"`
	InternalDetail string `json:"internal_detail,omitempty"`
	Registry       string `json:"registry,omitempty"`
	AllowlistHit   bool   `json:"allowlist_hit"`
	Bypass         string `json:"bypass,omitempty"` // "registry_flag" | "env_var" | "config_set" | "config_edit" | "userconfig_flag"
}

// Classifications carries top-level activity tags used by the audit pipeline.
type Classifications struct {
	IsShellCommand    bool `json:"is_shell_command,omitempty"`
	IsPackageManager  bool `json:"is_package_manager,omitempty"`
	IsMCPRelated      bool `json:"is_mcp_related,omitempty"`
	IsFileOperation   bool `json:"is_file_operation,omitempty"`
	IsNetworkActivity bool `json:"is_network_activity,omitempty"`
}

// IsZero reports whether no classification is set.
func (c Classifications) IsZero() bool {
	return c == (Classifications{})
}

// Enrichments holds optional, bounded enrichment payloads.
type Enrichments struct {
	Shell          *ShellEnrichment    `json:"shell,omitempty"`
	PackageManager *PackageManagerInfo `json:"package_manager,omitempty"`
	MCP            *MCPInfo            `json:"mcp,omitempty"`
	Secrets        *SecretsScanInfo    `json:"secrets,omitempty"`
}

// ShellEnrichment captures redacted shell-command context.
type ShellEnrichment struct {
	Command          string `json:"command,omitempty"`
	CommandTruncated bool   `json:"command_truncated,omitempty"`
	WorkingDirectory string `json:"working_directory,omitempty"`
}

// PackageManagerInfo records detection + diff results from a shell event.
type PackageManagerInfo struct {
	Detected        bool         `json:"detected"`
	Name            string       `json:"name,omitempty"`
	CommandKind     string       `json:"command_kind,omitempty"`
	Registry        string       `json:"registry,omitempty"`
	ConfigSources   []string     `json:"config_sources,omitempty"`
	PackagesAdded   []PackageRef `json:"packages_added,omitempty"`
	PackagesRemoved []PackageRef `json:"packages_removed,omitempty"`
	PackagesChanged []PackageRef `json:"packages_changed,omitempty"`
	Confidence      string       `json:"confidence,omitempty"`
	Evidence        []string     `json:"evidence,omitempty"`
}

// PackageRef is one package version reference in a diff.
type PackageRef struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// MCPInfo carries the non-derivable facts produced by parsing a
// shell-launched MCP server invocation. It is emitted ONLY when the
// shell command itself is the only signal that an MCP server is in
// play (e.g. `npx -y @modelcontextprotocol/server-foo` under a Bash
// tool call). Direct mcp__<server>__<tool> tool events, MCP permission
// events, and Elicitation hooks already carry the server identity in
// top-level fields or the payload, so they emit no MCPInfo block.
type MCPInfo struct {
	Kind          string `json:"kind,omitempty"`           // local | unknown
	ServerName    string `json:"server_name,omitempty"`    // parsed from package or command
	ServerCommand string `json:"server_command,omitempty"` // redacted, capped
}

// SecretsScanInfo summarizes session-end transcript scanning.
type SecretsScanInfo struct {
	Scanned   bool            `json:"scanned"`
	FilesSeen int             `json:"files_seen"`
	BytesSeen int64           `json:"bytes_seen"`
	Findings  []SecretFinding `json:"findings,omitempty"`
	TimedOut  bool            `json:"timed_out,omitempty"`
}

// SecretFinding is one redacted scanner hit. Full secret values are never
// stored; only a fingerprint and a masked preview.
type SecretFinding struct {
	RuleID        string `json:"rule_id"`
	FilePath      string `json:"file_path,omitempty"`
	LineStart     int    `json:"line_start,omitempty"`
	LineEnd       int    `json:"line_end,omitempty"`
	Fingerprint   string `json:"fingerprint,omitempty"`
	MaskedPreview string `json:"masked_preview,omitempty"`
	Confidence    string `json:"confidence,omitempty"`
}

// TimeoutInfo records that an enrichment hit its cap.
type TimeoutInfo struct {
	Stage   string        `json:"stage"`
	Cap     time.Duration `json:"cap_ns"`
	Elapsed time.Duration `json:"elapsed_ns"`
}

// ErrorInfo records a non-fatal internal error tied to this event.
type ErrorInfo struct {
	Stage   string `json:"stage"`
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// NewEventID returns a 128-bit random hex identifier.
func NewEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failures are vanishingly rare on any supported OS;
		// fall back to a timestamp-derived id rather than failing the hook.
		ts := time.Now().UnixNano()
		for i := range 8 {
			b[i] = byte(ts >> (8 * i))
		}
	}
	return hex.EncodeToString(b[:])
}
