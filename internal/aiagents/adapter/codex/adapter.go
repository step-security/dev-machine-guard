// Package codex implements the Adapter interface for OpenAI Codex.
//
// Detection is by `executor.LookPath("codex")` (plan §1.2). Codex
// stores hook configuration across two files:
//
//   - ~/.codex/hooks.json   — hook definitions (JSON)
//   - ~/.codex/config.toml  — global config; install also sets
//     `[features].codex_hooks = true` here so Codex actually invokes
//     hooks at runtime (plan §1.15)
//
// Uninstall removes DMG-owned hook entries from hooks.json but does
// NOT revert the codex_hooks feature flag — the user may have wired
// up other tools' hooks that depend on it (plan §1.15, documented as
// known residue in plan §4.6).
//
// Restore + Status are intentionally absent (see adapter.Adapter for
// the trimmed-interface rationale). There is no Force install option:
// the upsert path always refreshes managed entries in place, which
// covers the binary-move self-heal case the same way claudecode does.
package codex

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/configedit"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// AgentName is the identifier DMG uses for Codex on the wire and in
// the `_hook <agent>` invocation. Adapter-private; the runtime never
// compares against it.
const AgentName = "codex"

// AgentBinary is the name `executor.LookPath` searches for during
// detection. Adapter-private.
const AgentBinary = "codex"

// Adapter implements adapter.Adapter for OpenAI Codex.
//
// State is set once at construction and never mutated. hooksPath and
// configPath are derived from home; binaryPath is the absolute DMG
// binary path the install handler resolved via
// internal/aiagents/cli.Resolve.
type Adapter struct {
	hooksPath  string
	configPath string
	binaryPath string
}

// New constructs an Adapter for the given user home and resolved DMG
// binary path. Both arguments must be absolute; behavior with relative
// paths is undefined.
func New(home, binaryPath string) *Adapter {
	return &Adapter{
		hooksPath:  filepath.Join(home, ".codex", "hooks.json"),
		configPath: filepath.Join(home, ".codex", "config.toml"),
		binaryPath: binaryPath,
	}
}

// Name returns the adapter agent name.
func (a *Adapter) Name() string { return AgentName }

// ManagedFiles enumerates the two files Codex install/uninstall
// mutates. Used by the install handler for the chown sweep under root.
func (a *Adapter) ManagedFiles() []adapter.ManagedFile {
	return []adapter.ManagedFile{
		{Label: "~/.codex/hooks.json", Path: a.hooksPath},
		{Label: "~/.codex/config.toml", Path: a.configPath},
	}
}

// Detect reports whether the Codex CLI is on $PATH (plan §1.2).
// Settings file presence is NOT a gate — install creates the files
// from scratch when absent.
func (a *Adapter) Detect(ctx context.Context, exec executor.Executor) (adapter.DetectionResult, error) {
	res := adapter.DetectionResult{}
	bin, err := exec.LookPath(AgentBinary)
	if err != nil {
		res.Notes = append(res.Notes, "codex CLI not found on $PATH")
		return res, nil
	}
	res.Detected = true
	res.BinaryPath = bin
	return res, nil
}

// Install adds DMG-owned hooks to hooks.json and ensures the
// `[features].codex_hooks=true` flag in config.toml.
//
// Multi-file safety: every output buffer (hooks.json + config.toml)
// is loaded, validated, and encoded BEFORE the first write happens —
// a malformed config.toml aborts the operation with hooks.json still
// intact. The plan explicitly forbids partial-write states (plan §1.4
// implicit; surfaced by Anchor's TestInstallMalformedTOMLDoesNotMutateHooks).
//
// Idempotent: when both files are already in desired state, returns
// empty WrittenFiles and BackupFiles and performs no writes.
func (a *Adapter) Install(ctx context.Context) (adapter.InstallResult, error) {
	res := adapter.InstallResult{}

	// Load+validate-encode both files BEFORE writing either.
	doc, err := loadHooksDoc(a.hooksPath)
	if err != nil {
		return res, err
	}
	cfgBytes, err := loadConfigTOMLBytes(a.configPath)
	if err != nil {
		return res, err
	}

	for _, ht := range supportedHookEvents {
		if doc.upsertHook(ht, a.commandFor(ht)) {
			res.HooksAdded = append(res.HooksAdded, ht)
		} else {
			res.HooksKept = append(res.HooksKept, ht)
		}
	}
	patchedCfg, flagChanged, err := configedit.EnsureCodexHooksFlag(cfgBytes)
	if err != nil {
		return res, err
	}

	hooksWR, err := writeHooksAtomic(a.hooksPath, doc)
	if err != nil {
		return res, err
	}
	if hooksWR != nil {
		res.WrittenFiles = append(res.WrittenFiles, hooksWR.Path)
		if hooksWR.BackupPath != "" {
			res.BackupFiles = append(res.BackupFiles, hooksWR.BackupPath)
		}
		res.CreatedDirs = append(res.CreatedDirs, hooksWR.CreatedDirs...)
	}

	if flagChanged {
		cfgWR, err := writeConfigAtomic(a.configPath, patchedCfg)
		if err != nil {
			return res, err
		}
		if cfgWR != nil {
			res.WrittenFiles = append(res.WrittenFiles, cfgWR.Path)
			if cfgWR.BackupPath != "" {
				res.BackupFiles = append(res.BackupFiles, cfgWR.BackupPath)
			}
			res.CreatedDirs = appendUnique(res.CreatedDirs, cfgWR.CreatedDirs...)
		}
		res.Notes = append(res.Notes, "enabled [features].codex_hooks=true in "+a.configPath)
	}
	return res, nil
}

// Uninstall removes DMG-owned hook entries from hooks.json. The
// `[features].codex_hooks` flag in config.toml is intentionally NOT
// reverted — the user may have other tools' hooks that depend on it
// being enabled (plan §1.15).
//
// The settings file is preserved even when uninstall removes the last
// hook — leaving an empty {} (or whatever non-hook keys remain) keeps
// any user customization intact.
func (a *Adapter) Uninstall(ctx context.Context) (adapter.UninstallResult, error) {
	res := adapter.UninstallResult{}

	doc, err := loadHooksDoc(a.hooksPath)
	if err != nil {
		return res, err
	}
	res.HooksRemoved = doc.removeManagedHooks(a.binaryPath)
	if len(res.HooksRemoved) == 0 {
		res.Notes = append(res.Notes, "no DMG-owned Codex hook entries found")
		res.Notes = append(res.Notes, "Codex hooks feature flag left enabled because non-DMG hooks may exist")
		return res, nil
	}
	wr, err := writeHooksAtomic(a.hooksPath, doc)
	if err != nil {
		return res, fmt.Errorf("codex uninstall: %w", err)
	}
	if wr != nil {
		res.WrittenFiles = append(res.WrittenFiles, wr.Path)
		if wr.BackupPath != "" {
			res.BackupFiles = append(res.BackupFiles, wr.BackupPath)
		}
	}
	res.Notes = append(res.Notes, "Codex hooks feature flag left enabled because non-DMG hooks may exist")
	return res, nil
}

// commandFor renders the literal command string DMG writes into the
// settings entry for hookEvent. Format (plan §1.3):
//
//	<binaryPath> _hook codex <hookEvent>
//
// The binary path is absolute and symlink-resolved at install time;
// see internal/aiagents/cli/selfpath.go.
func (a *Adapter) commandFor(hookEvent event.HookEvent) string {
	return a.binaryPath + " _hook " + AgentName + " " + string(hookEvent)
}

// noopResponse marshals to {} — Codex treats empty output / {} as
// "continue, no decision". It is the default for every hook event.
type noopResponse struct{}

// preToolUseDeny is the spec-compliant Codex deny shape. Used only on
// PreToolUse block decisions.
type preToolUseDeny struct {
	HookSpecificOutput map[string]any `json:"hookSpecificOutput"`
}

// DecideResponse renders a generic Decision into Codex's wire format.
// Default is the empty object {}; only PreToolUse + Allow=false
// produces the hook-specific deny shape.
//
// Phase 1 NEVER returns Allow=false to the agent: the policy
// evaluator is forced to audit mode (plan §1.9). The Allow=false path
// is exercised only by adapter unit tests until block mode ships.
func (a *Adapter) DecideResponse(ev *event.Event, d adapter.Decision) adapter.HookResponse {
	if d.Allow || ev == nil {
		return noopResponse{}
	}
	if ev.HookPhase == event.HookPhasePreTool {
		msg := d.UserMessage
		if msg == "" {
			msg = "Blocked by your organization's administrator."
		}
		return preToolUseDeny{
			HookSpecificOutput: map[string]any{
				"hookEventName":            string(HookPreToolUse),
				"permissionDecision":       "deny",
				"permissionDecisionReason": msg,
			},
		}
	}
	return noopResponse{}
}

// appendUnique appends each item to base if not already present,
// preserving base's order. Used to merge CreatedDirs from two
// atomicfile writes that share a parent (~/.codex/).
func appendUnique(base []string, items ...string) []string {
	for _, it := range items {
		if !slices.Contains(base, it) {
			base = append(base, it)
		}
	}
	return base
}
