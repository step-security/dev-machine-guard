// Package hook implements the bounded, fail-open hot path invoked by
// `stepsecurity-dev-machine-guard _hook <agent> <hookEvent>`. Every stage
// MUST be capped, redaction-first, and resilient to internal errors:
// the agent waits for stdout, so a failure here can never become a
// non-zero exit or a stalled response.
//
// Persistence-by-design omission: this package does NOT write
// events.jsonl. The only on-disk artifact is the errors log appended
// through the LogError seam; the event itself is either delivered to
// UploadEvent or dropped.
package hook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/enrich/mcp"
	"github.com/step-security/dev-machine-guard/internal/aiagents/enrich/npm"
	"github.com/step-security/dev-machine-guard/internal/aiagents/enrich/secrets"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/identity"
	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/aiagents/policy"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// Every hook invocation MUST honor these caps.
//
// CapHook bounds the worst-case agent stall on a hung invocation. It is
// 15s to absorb the 1s identity probe and a
// 5s upload under load. The agent's own hook timeout (Claude Code
// defaults to 60s) is the absolute ceiling above us.
const (
	CapHook       = 15 * time.Second
	CapPM         = 10 * time.Second
	CapMCP        = 10 * time.Second
	CapSecretMin  = 30 * time.Second
	CapSecretMax  = 60 * time.Second
	MaxStdinBytes = 5 * 1024 * 1024 // 5 MiB
)

// UploadTimeout is the per-invocation cap on the synchronous upload
// stage. Mirrors ingest.DefaultHookUploadTimeout; kept here so the
// runtime stays decoupled from the ingest package's HTTP client.
const UploadTimeout = 5 * time.Second

// Runtime wires every dependency the hot path needs.
//
// All fields are exported so tests and the CLI handler can construct a
// Runtime by struct literal. Production code prefers NewRuntime, which
// fills in defaults (real executor, os.Std{in,out,err}, UTC clock).
type Runtime struct {
	Adapter adapter.Adapter
	Exec    executor.Executor
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Now     func() time.Time

	// Policy, when non-nil, overrides the embedded builtin. Production
	// code leaves this nil; tests inject mode/allowlist variants.
	Policy *policy.Policy

	// UploadEvent is the synchronous backend ingestion seam. nil means
	// upload is disabled — the local-only behavior the runtime falls
	// back to whenever enterprise config is missing. Production wires
	// this to an ingest.Client closure via cli.newUploader; tests
	// inject a capture function. The event passed in already carries
	// customer_id, device_id, and user_identity stamped from the same
	// identity.Resolve call, so the seam intentionally does not take a
	// separate identity argument.
	UploadEvent func(ctx context.Context, ev event.Event) error

	// LogError is the errors.jsonl appender seam. nil means errors are
	// silently dropped — fail-open is the contract; logging is best
	// effort. Production wires this to cli.AppendError; tests can
	// capture the calls by setting their own function. Signature
	// matches cli.AppendError(stage, code, message, eventID).
	LogError func(stage, code, message, eventID string)
}

// NewRuntime constructs the default runtime for the given adapter. The
// hook package no longer knows about any concrete adapter; agent
// selection is the CLI's job.
func NewRuntime(a adapter.Adapter) *Runtime {
	return &Runtime{
		Adapter: a,
		Exec:    executor.NewReal(),
		Stdin:   os.Stdin,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
		Now:     func() time.Time { return time.Now().UTC() },
	}
}

// Run executes one hook invocation. It always writes an adapter-compatible
// response to stdout, even on internal failure. The default verdict is
// allow; only an explicit policy match flips it to block.
//
// The returned error, if any, is purely informational for the CLI exit
// path: the CLI swallows it so the process exit code stays 0.
func (rt *Runtime) Run(parent context.Context, hookType event.HookEvent) error {
	ctx, cancel := context.WithTimeout(parent, CapHook)
	defer cancel()

	// The deferred emit reads these captured variables. Defaults: allow
	// decision, no parsed event (the parse may fail before `ev` is set).
	// The policy stage is the only thing that overwrites `decision`. Any
	// failure path leaves it at allow, preserving fail-open. The closure
	// reads both at deferred-execution time, so later assignments to `ev`
	// and `decision` are visible.
	decision := adapter.AllowDecision()
	var ev *event.Event
	defer func() { rt.emitDecidedResponse(ev, decision) }()

	cfg, _ := ingest.Snapshot()
	id := identity.Resolve(ctx, rt.Exec, cfg.CustomerID)
	upload := rt.resolveUpload()

	raw, readErr := readBounded(rt.Stdin, MaxStdinBytes)
	if readErr != nil {
		if errors.Is(readErr, errInputTooLarge) {
			rt.logError("stdin", "input_too_large", readErr.Error(), "")
			return readErr
		}
		rt.logError("stdin", "read_error", readErr.Error(), "")
		return readErr
	}

	parsed, parseErr := rt.Adapter.ParseEvent(ctx, hookType, raw)
	if parseErr != nil {
		rt.logError("parse", "parse_error", parseErr.Error(), "")
		return parseErr
	}
	ev = parsed

	// Stamp identity. AgentVersion is intentionally not stamped here —
	// it would have to come from the adapter or hook payload, and Claude
	// Code does not include it in the hook payload today. The field stays
	// empty until there is a real source.
	ev.CustomerID = id.CustomerID
	ev.UserIdentity = id.UserIdentity
	ev.DeviceID = id.DeviceID

	// Classify before enrichment so even fast paths get the bool flags.
	classify(ev)

	// From here on, ev.HookEvent is the source of truth. ParseEvent keeps it
	// aligned with the CLI hook arg and records any payload hook_event_name
	// mismatch in ev.Errors, so policy evaluation and response rendering use
	// the same hook type.

	// Extract the shell command once. The adapter owns shell extraction;
	// the runtime hands the redacted command to enrichments and policy.
	shellCmd, shellCwd, hasShell := rt.Adapter.ShellCommand(ev)

	// Run enrichments under their own caps.
	rt.runEnrichments(ctx, ev, shellCmd, shellCwd, hasShell)

	// Policy evaluation. Fail-open: only an explicit block decision
	// overwrites `decision`; every error path inside leaves the default
	// allow in place. Phase-based gate keeps cross-agent correctness:
	// pre_tool + command_exec + a shell command in hand.
	if shouldEvaluatePolicy(ev, shellCmd) {
		if info, d := rt.evaluatePolicy(ctx, ev, shellCmd); info != nil {
			ev.PolicyDecision = info
			if !d.Allow {
				decision = d
			}
		}
	}

	// Re-redact final event (defense in depth) before upload.
	if ev.Payload != nil {
		if m, ok := redact.Value(ev.Payload).(map[string]any); ok {
			ev.Payload = m
		}
	}

	// Synchronous upload, fail-open. The agent response has not been
	// emitted yet — the deferred emit fires after Run returns — so any
	// time spent here directly delays the agent. The upload context is
	// capped at UploadTimeout to bound that delay even when the backend
	// hangs.
	//
	// Failure is recorded only in errors.jsonl; the event is dropped.
	if upload != nil {
		uploadCtx, cancel := context.WithTimeout(ctx, UploadTimeout)
		uploadErr := upload(uploadCtx, *ev)
		cancel()
		if uploadErr != nil {
			rt.logError("ingest", "upload_error", uploadErr.Error(), ev.EventID)
		}
	}
	return nil
}

// resolveUpload picks the upload function for this hook invocation.
// Tests override Runtime.UploadEvent directly; production code wires
// it through cli.newUploader, which returns nil whenever enterprise
// config is missing. A nil UploadEvent disables upload — the
// local-only fallback we want without enterprise credentials.
func (rt *Runtime) resolveUpload() func(context.Context, event.Event) error {
	return rt.UploadEvent
}

// emitDecidedResponse writes the adapter's wire-format response for the
// final decision. Both ev and dec are captured by the deferred closure
// in Run so the values reflect whatever the runtime had reached when
// it returned. ev is nil on parse-error paths; the adapter handles that
// as allow.
//
// Errors marshaling are intentionally swallowed; both Claude Code and
// Codex accept an empty body as "allow", so we always succeed at fail-open.
func (rt *Runtime) emitDecidedResponse(ev *event.Event, dec adapter.Decision) {
	resp := rt.Adapter.DecideResponse(ev, dec)
	b, err := json.Marshal(resp)
	if err != nil {
		_, _ = io.WriteString(rt.Stdout, "{}\n")
		return
	}
	_, _ = rt.Stdout.Write(b)
	_, _ = io.WriteString(rt.Stdout, "\n")
}

// logError forwards to the LogError seam. nil seam means errors are
// silently dropped, preserving the fail-open contract end-to-end.
func (rt *Runtime) logError(stage, code, message, eventID string) {
	if rt.LogError == nil {
		return
	}
	rt.LogError(stage, code, message, eventID)
}

func classify(ev *event.Event) {
	cls := event.Classifications{}
	switch ev.ActionType {
	case event.ActionCommandExec:
		cls.IsShellCommand = true
	case event.ActionFileRead, event.ActionFileWrite, event.ActionFileDelete:
		cls.IsFileOperation = true
	case event.ActionNetworkRequest:
		cls.IsNetworkActivity = true
	case event.ActionMCPInvocation:
		cls.IsMCPRelated = true
	}
	// Lifecycle MCP signals: phase alone (or tool_name prefix on
	// permission phases) is enough to set the broad filter, no enrichment
	// block required. Branching on HookPhase rather than the native
	// HookEvent keeps this correct for any future adapter whose native
	// hook names differ from Claude's.
	switch ev.HookPhase {
	case event.HookPhaseElicitation, event.HookPhaseElicitationResult:
		cls.IsMCPRelated = true
	case event.HookPhasePermissionRequest, event.HookPhasePermissionDenied:
		if strings.HasPrefix(strings.ToLower(ev.ToolName), "mcp__") {
			cls.IsMCPRelated = true
		}
	}
	if !cls.IsZero() {
		ev.Classifications = &cls
	}
}

func (rt *Runtime) runEnrichments(parent context.Context, ev *event.Event, cmd, cwd string, hasShell bool) {
	// Shell command capture + package-manager enrichment.
	if hasShell {
		ev.Enrichments = ensureEnrich(ev.Enrichments)
		ev.Enrichments.Shell = &event.ShellEnrichment{
			Command:          truncate(redact.String(cmd), 4096),
			CommandTruncated: len(cmd) > 4096,
			WorkingDirectory: cwd,
		}
		// Package manager
		pmCtx, cancel := context.WithTimeout(parent, CapPM)
		started := time.Now()
		pmInfo, pmTimedOut := npm.Enrich(pmCtx, cmd, cwd)
		cancel()
		if pmInfo != nil {
			ev.Enrichments.PackageManager = pmInfo
			if ev.Classifications == nil {
				ev.Classifications = &event.Classifications{}
			}
			ev.Classifications.IsPackageManager = pmInfo.Detected
		}
		if pmTimedOut {
			ev.Timeouts = append(ev.Timeouts, event.TimeoutInfo{
				Stage: "package_manager", Cap: CapPM, Elapsed: time.Since(started),
			})
			rt.logError("enrich_pm", "enrichment_timeout", "package manager enrichment exceeded cap", "")
		}

		// MCP from shell evidence: only emitted when parsing the
		// command actually surfaces a server. Direct mcp__<server>__<tool>
		// tool events, MCP permission events, and Elicitation hooks
		// produce no MCPInfo block — their server identity is already
		// in tool_name or the payload. classify() sets is_mcp_related
		// for those cases from the hook event alone.
		mcpCtx, cancelMCP := context.WithTimeout(parent, CapMCP)
		startedMCP := time.Now()
		mcpInfo, mcpTimedOut := mcp.ClassifyShell(mcpCtx, cmd)
		cancelMCP()
		if mcpInfo != nil {
			ev.Enrichments.MCP = mcpInfo
			if ev.Classifications == nil {
				ev.Classifications = &event.Classifications{}
			}
			ev.Classifications.IsMCPRelated = true
		}
		if mcpTimedOut {
			ev.Timeouts = append(ev.Timeouts, event.TimeoutInfo{
				Stage: "mcp", Cap: CapMCP, Elapsed: time.Since(startedMCP),
			})
			rt.logError("enrich_mcp", "enrichment_timeout", "mcp enrichment exceeded cap", "")
		}
	}

	// Session-end secret scanner. Bounded and runs only when a transcript
	// path is present in the payload. Phase-keyed so any adapter mapping
	// its session-end equivalent to HookPhaseSessionEnd gets the scan.
	if ev.HookPhase == event.HookPhaseSessionEnd {
		transcript, _ := ev.Payload["transcript_path"].(string)
		if transcript != "" {
			scanCtx, cancel := context.WithTimeout(parent, CapSecretMin)
			started := time.Now()
			info, timedOut := secrets.ScanTranscript(scanCtx, transcript)
			cancel()
			if info != nil {
				ev.Enrichments = ensureEnrich(ev.Enrichments)
				ev.Enrichments.Secrets = info
			}
			if timedOut {
				ev.Timeouts = append(ev.Timeouts, event.TimeoutInfo{
					Stage: "secret_scan", Cap: CapSecretMin, Elapsed: time.Since(started),
				})
				rt.logError("enrich_secrets", "enrichment_timeout", "secret scan exceeded cap", "")
			}
		}
	}
}

func ensureEnrich(e *event.Enrichments) *event.Enrichments {
	if e != nil {
		return e
	}
	return &event.Enrichments{}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
