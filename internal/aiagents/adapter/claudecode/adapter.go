// Package claudecode implements the Adapter interface for Claude Code.
//
// Detection is by `executor.LookPath("claude")`. Settings live at
// <home>/.claude/settings.json. The hook command DMG writes is
// `<binaryPath> _hook claude-code <hookEvent>` where binaryPath is the
// absolute, symlink-resolved DMG binary path resolved at install time.
//
// Restore + Status are intentionally absent — see the package-level
// doc on adapter.Adapter for why the interface is trimmed.
package claudecode

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// AgentName is the identifier DMG uses for Claude Code on the wire and
// in the `_hook <agent>` invocation. Adapter-private; the runtime
// never compares against it.
const AgentName = "claude-code"

// AgentBinary is the name `executor.LookPath` searches for during
// detection. Adapter-private.
const AgentBinary = "claude"

// Adapter implements adapter.Adapter for Claude Code.
//
// State is set once at construction and never mutated. settingsPath is
// derived from home; binaryPath is the absolute DMG binary path the
// install handler resolved via internal/aiagents/cli.Resolve.
type Adapter struct {
	settingsPath string
	binaryPath   string
}

// New constructs an Adapter for the given user home and resolved DMG
// binary path. Both arguments must be absolute; behavior with relative
// paths is undefined.
func New(home, binaryPath string) *Adapter {
	return &Adapter{
		settingsPath: filepath.Join(home, ".claude", "settings.json"),
		binaryPath:   binaryPath,
	}
}

// Name returns the adapter agent name.
func (a *Adapter) Name() string { return AgentName }

// ManagedFiles reports the single Claude settings file the adapter
// mutates. Used by the install handler for the chown sweep under root.
func (a *Adapter) ManagedFiles() []adapter.ManagedFile {
	return []adapter.ManagedFile{{Label: "~/.claude/settings.json", Path: a.settingsPath}}
}

// Detect reports whether the Claude Code CLI is on $PATH. Settings
// file presence is NOT a gate — install creates the file from scratch
// when absent.
func (a *Adapter) Detect(ctx context.Context, exec executor.Executor) (adapter.DetectionResult, error) {
	res := adapter.DetectionResult{}
	bin, err := exec.LookPath(AgentBinary)
	if err != nil {
		// LookPath errors mean "not on $PATH" — that's a query result,
		// not an operational failure.
		res.Notes = append(res.Notes, "claude CLI not found on $PATH")
		return res, nil
	}
	res.Detected = true
	res.BinaryPath = bin
	return res, nil
}

// Install adds DMG-owned hooks for every supported hook event.
//
// Idempotent: when every entry is already in place, no file is written
// and HooksKept enumerates every event. When any entry is added or
// refreshed, the entire settings file is pretty-printed to canonical
// 2-space indent — formatting in keys we did not touch is normalized
// once on edit, which is an acceptable trade-off for human readability
// of the result.
func (a *Adapter) Install(ctx context.Context) (adapter.InstallResult, error) {
	doc, err := loadSettings(a.settingsPath)
	if err != nil {
		return adapter.InstallResult{}, err
	}
	res := adapter.InstallResult{}
	for _, ht := range supportedHookEvents {
		if doc.upsertHook(ht, a.commandFor(ht)) {
			res.HooksAdded = append(res.HooksAdded, ht)
		} else {
			res.HooksKept = append(res.HooksKept, ht)
		}
	}
	wr, err := writeAtomic(a.settingsPath, doc)
	if err != nil {
		return res, err
	}
	if wr != nil {
		res.WrittenFiles = append(res.WrittenFiles, wr.Path)
		if wr.BackupPath != "" {
			res.BackupFiles = append(res.BackupFiles, wr.BackupPath)
		}
		res.CreatedDirs = append(res.CreatedDirs, wr.CreatedDirs...)
	}
	return res, nil
}

// Uninstall removes only DMG-owned hook entries.
// The settings file is preserved even when uninstall removes the last
// hook — leaving an empty {} (or whatever non-hook keys remain) keeps
// any user customization intact.
func (a *Adapter) Uninstall(ctx context.Context) (adapter.UninstallResult, error) {
	doc, err := loadSettings(a.settingsPath)
	if err != nil {
		return adapter.UninstallResult{}, err
	}
	res := adapter.UninstallResult{}
	res.HooksRemoved = doc.removeManagedHooks(a.binaryPath)
	if len(res.HooksRemoved) == 0 {
		res.Notes = append(res.Notes, "no DMG-owned hook entries found")
		return res, nil
	}
	wr, err := writeAtomic(a.settingsPath, doc)
	if err != nil {
		return res, fmt.Errorf("claude uninstall: %w", err)
	}
	if wr != nil {
		res.WrittenFiles = append(res.WrittenFiles, wr.Path)
		if wr.BackupPath != "" {
			res.BackupFiles = append(res.BackupFiles, wr.BackupPath)
		}
	}
	return res, nil
}

// commandFor renders the literal command string DMG writes into the
// settings entry for hookEvent. Format:
//
//	<binaryPath> _hook claude-code <hookEvent>
//
// The binary path is absolute and symlink-resolved at install time;
// see internal/aiagents/cli/selfpath.go.
func (a *Adapter) commandFor(hookEvent event.HookEvent) string {
	return a.binaryPath + " _hook " + AgentName + " " + string(hookEvent)
}

// allowResponse is the Claude Code wire-format for "let the agent
// proceed." `{"continue": true, "suppressOutput": true}` is the
// canonical allow shape on every hook event.
type allowResponse struct {
	Continue       bool `json:"continue"`
	SuppressOutput bool `json:"suppressOutput,omitempty"`
}

// preToolUseBlockResponse is the spec-compliant PreToolUse block shape.
// Per https://code.claude.com/docs/en/hooks.md, blocking a tool call
// MUST go through hookSpecificOutput.permissionDecision; the legacy
// top-level `decision: "block"` is deprecated. We never emit
// `continue: false` — that field halts the agent entirely and is
// scope-mismatched for "block this single tool call."
type preToolUseBlockResponse struct {
	SuppressOutput     bool           `json:"suppressOutput,omitempty"`
	HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
}

// DecideResponse renders a generic Decision into Claude Code's wire
// format. Routing is hook-type-aware: only PreToolUse has a defined
// block path today (the policy stage is filtered to PreToolUse + Bash).
// Every other hook event renders the generic allow shape on both
// allow and (defensively) on block, so a stray block decision can
// never accidentally halt the agent.
func (a *Adapter) DecideResponse(ev *event.Event, d adapter.Decision) adapter.HookResponse {
	if d.Allow || ev == nil {
		return allowResponse{Continue: true, SuppressOutput: true}
	}
	switch ev.HookEvent {
	case event.HookPreToolUse:
		msg := d.UserMessage
		if msg == "" {
			msg = "Blocked by your organization's administrator."
		}
		return preToolUseBlockResponse{
			SuppressOutput: true,
			HookSpecificOutput: map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": msg,
			},
		}
	default:
		return allowResponse{Continue: true, SuppressOutput: true}
	}
}
