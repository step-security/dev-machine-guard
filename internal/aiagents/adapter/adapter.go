// Package adapter defines the contract every per-agent integration
// (Claude Code, Codex) implements.
//
// Lifecycle of an Adapter:
//
//   - hooks install handler   ⇢  Detect, ManagedFiles, Install
//   - hooks uninstall handler ⇢  ManagedFiles, Uninstall
//   - _hook runtime           ⇢  ParseEvent, ShellCommand, DecideResponse
//
// The interface is intentionally trimmed: Restore, Status,
// RestoreOptions, BackupInfo, and HookStatus are absent — `hooks restore`
// and `hooks status` are not in scope. Reintroducing them is a public-API
// change, so adapters should not invent stubs that hint they are coming
// back.
//
// Constructors take the user's home directory and the resolved DMG
// binary path. Adapters compute their own settings file paths (e.g.
// ~/.claude/settings.json, ~/.codex/{hooks.json,config.toml}) from
// home, and embed binaryPath (absolute, symlinks resolved) into the
// hook command they write into settings. Both pieces of state are
// immutable for the lifetime of the adapter.
package adapter

import (
	"context"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// DetectionResult reports whether the agent is installed locally.
//
// Detection is by executor.LookPath of the agent's CLI binary
// (claude / codex). Settings file presence is NOT a gate — install
// creates the settings file from scratch when absent.
type DetectionResult struct {
	// Detected is true iff the agent's CLI binary is on $PATH.
	Detected bool

	// BinaryPath is the resolved absolute path returned by LookPath
	// when Detected=true; empty otherwise. Diagnostic only — install
	// does not invoke the agent binary.
	BinaryPath string

	// Notes are user-facing diagnostic strings. Examples: "settings
	// file does not exist; install will create it".
	Notes []string
}

// ManagedFile describes one file an adapter mutates. The install /
// uninstall handlers consult this list so they never have to hardcode
// per-agent paths or labels — and the install handler walks it (plus
// CreatedDirs from InstallResult) to chown the full set under root.
type ManagedFile struct {
	// Label is the user-facing path with $HOME tildified (e.g.
	// "~/.claude/settings.json"). Used in diagnostic output.
	Label string
	// Path is the absolute filesystem path.
	Path string
}

// InstallResult describes what install actually did.
//
// The install handler walks WrittenFiles ∪ BackupFiles ∪ CreatedDirs
// to chown the full set to the console user under root. Adapters must
// populate all three slices.
type InstallResult struct {
	// HooksAdded names the hook events for which a new entry was
	// added. Order matches the adapter's SupportedHooks() order.
	HooksAdded []event.HookEvent

	// HooksKept names hook events whose entry was already in place
	// and untouched (idempotent reinstall).
	HooksKept []event.HookEvent

	// WrittenFiles are settings files (and side-effect files such as
	// Codex's config.toml) that Install created or rewrote. Absolute
	// paths only. Empty when the install was a complete no-op.
	WrittenFiles []string

	// BackupFiles are pre-existing files Install copied aside before
	// rewriting, named with the .dmg-backup.<UTC stamp> suffix from
	// internal/aiagents/atomicfile.
	BackupFiles []string

	// CreatedDirs are parent directories Install mkdir'd. Order is
	// shallowest-first so chown can apply parent-before-child without
	// a second pass.
	CreatedDirs []string

	// Notes are user-facing diagnostic strings.
	Notes []string
}

// UninstallResult describes the side effects of uninstall.
//
// The settings file is never deleted, even when uninstall removes the
// last entry — leaving an empty settings object behind preserves any
// non-hook configuration the user had in there.
type UninstallResult struct {
	// HooksRemoved names hook events from which at least one
	// DMG-owned entry was removed. Sorted for stable output.
	HooksRemoved []event.HookEvent

	// WrittenFiles are settings files Uninstall rewrote.
	WrittenFiles []string

	// BackupFiles are pre-existing settings files copied aside before
	// rewrite, with the .dmg-backup.<UTC stamp> suffix.
	BackupFiles []string

	// Notes are user-facing diagnostic strings.
	Notes []string
}

// Decision is the agent-agnostic verdict the runtime hands to
// DecideResponse. It carries ONLY the two fields the wire format
// actually needs; the richer event.PolicyDecisionInfo (with code,
// internal detail, would_block, etc.) lives on the event itself.
//
// A zero-value Decision means "deny with no reason" — callers should
// always construct via AllowDecision() or with explicit Allow=true.
//
// Today the runtime NEVER returns Allow=false to the agent: the policy
// evaluator is forced to audit mode. DecideResponse implementations
// must still handle Allow=false correctly because the same code path
// will serve block mode in a future revision.
type Decision struct {
	Allow bool
	// UserMessage is shown on block; ignored on allow. The fixed
	// user-visible deny string is "Blocked by your organization's
	// administrator." — UserMessage is the upstream rationale used
	// in telemetry, not what the end user sees.
	UserMessage string
}

// AllowDecision is the canonical zero-message allow.
func AllowDecision() Decision { return Decision{Allow: true} }

// HookResponse is the adapter-agnostic return type from DecideResponse.
// The runtime treats it as opaque and json-marshals it to stdout; the
// concrete shape is the adapter's responsibility and lives inside the
// adapter's own subpackage. This boundary is what lets future adapters
// define their own wire format without bleeding into the hot path or
// any shared type.
type HookResponse any

// BackupInfo is the value side of (path, timestamp) backup entries.
// Reserved here for future hooks-restore work; not used by current
// install/uninstall but kept on the public API so adding it later
// does not require a fresh type. (Held in this package because
// atomicfile and the install handler share the (path, time) pair.)
type BackupInfo struct {
	Path      string
	Timestamp time.Time
}

// Adapter is the per-agent integration contract.
//
// Implementations must be safe to construct cheaply (the install
// handler builds one per detected agent) and stateless across method
// calls — adapter state is set at construction time (home dir, binary
// path) and not mutated by methods. Each method receives any per-call
// inputs explicitly so the adapter does not coordinate shared state.
type Adapter interface {
	// Name is the canonical agent slug used on the CLI (`--agent
	// <name>`), in the `_hook <name>` runtime invocation, and in the
	// event payload. Returns "claude-code" or "codex".
	Name() string

	// SupportedHooks returns the agent-defined hook events DMG
	// installs entries for. Order is preserved in user-facing
	// install diagnostics. Returned slice is owned by the caller.
	SupportedHooks() []event.HookEvent

	// ManagedFiles enumerates every file this adapter mutates,
	// computed from the home directory baked in at construction
	// time. Used by the install handler for the chown sweep under
	// root and by uninstall to know what to inspect.
	ManagedFiles() []ManagedFile

	// Detect reports whether the agent is installed on this machine.
	// Implementations call exec.LookPath on the agent's CLI binary;
	// any LookPath error becomes Detected=false (no error return —
	// detection is a query, not an operation).
	Detect(ctx context.Context, exec executor.Executor) (DetectionResult, error)

	// Install writes hook entries into the agent's settings file(s).
	// Idempotent: when the entries are already present and unchanged,
	// returns empty WrittenFiles and BackupFiles and performs no
	// writes.
	//
	// Multi-file adapters (Codex writes both hooks.json and
	// config.toml) MUST validate-and-encode every output buffer
	// before writing the first one — a half-applied install leaves
	// the agent in a worse state than no install.
	Install(ctx context.Context) (InstallResult, error)

	// Uninstall removes DMG-owned hook entries from the agent's
	// settings. Match criterion: the entry's command field matches
	// the per-adapter pattern derived from the resolved DMG binary
	// path. Third-party hooks from other tools are intentionally not
	// matched.
	//
	// The settings file is never deleted, even if uninstall empties
	// it of hooks.
	Uninstall(ctx context.Context) (UninstallResult, error)

	// ParseEvent decodes a payload that the agent piped to
	// `_hook <agent> <event>` on stdin. The runtime reads stdin
	// (capped at 5 MiB by hook/stdin.go), and passes the hookType
	// from the CLI args plus the raw bytes here. The CLI arg is the
	// canonical hookType — payload mismatches are recorded as
	// event.ErrorInfo, not promoted to the wire field.
	//
	// Errors are returned verbatim. The runtime's fail-open contract
	// (cli/hook.go) means a ParseEvent error becomes an allow
	// response on stdout, with the error logged to errlog.
	ParseEvent(ctx context.Context, hookType event.HookEvent, raw []byte) (*event.Event, error)

	// ShellCommand extracts the redacted shell command (and its
	// working directory) from a parsed event, when the underlying
	// tool is a shell. Adapters whose agents have no shell tool
	// return ok=false. The returned command is already redacted.
	ShellCommand(ev *event.Event) (cmd string, cwd string, ok bool)

	// DecideResponse renders a Decision into the agent's expected
	// stdout response shape. The runtime json-marshals the result
	// and writes it to stdout verbatim.
	//
	// The runtime always passes AllowDecision() today. The Allow=false
	// path is exercised only by adapter unit tests until block mode
	// ships.
	DecideResponse(ev *event.Event, d Decision) HookResponse
}
