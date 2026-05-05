// Package cli houses entry points for the AI-agent hooks domain:
// `hooks install`, `hooks uninstall`, and the hidden `_hook` runtime.
//
// The runtime entry point intentionally lives outside internal/cli so the
// hot path can bypass cli.Parse and logger construction — agents invoke
// `_hook` on every event and a non-zero exit is treated as a hook
// failure / block. RunHook does call config.Load itself (Phase 3
// requires it for the upload gate); the bypass is everything else in
// main's startup path. Fail-open is a hard contract enforced here.
package cli

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter/claudecode"
	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter/codex"
	aieventc "github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/hook"
	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// RunHook is the hidden `_hook <agent> <event>` entry point.
//
// Contract (enforced by hook_test.go and main_test.go):
//   - returns 0 on every code path, including malformed args, unknown agents,
//     unparseable stdin, and internal panics
//   - writes nothing to stdout unless emitting a valid agent-allow response
//   - writes nothing to stderr on the success path
//
// args is os.Args[2:] — i.e., everything after the `_hook` verb. Two
// positional args are required (agent, hookEvent) and any additional or
// missing args fail-open silently.
func RunHook(stdin io.Reader, stdout, stderr io.Writer, args []string) int {
	defer func() {
		// Last-line defense: a panic anywhere in the runtime must still
		// translate to exit 0 with no stdout. The recover swallows any
		// stack trace so it never leaks to the agent.
		_ = recover()
	}()

	if len(args) != 2 {
		return 0
	}
	agent, hookEvent := args[0], args[1]
	if agent == "" || hookEvent == "" {
		return 0
	}

	ad := adapterForHookAgent(agent)
	if ad == nil {
		return 0
	}

	// Load process-wide config so ingest.Snapshot below sees the
	// per-user credentials persisted by `configure`. Load is a silent
	// no-op when the file is missing or malformed; the snapshot gate
	// is the only thing that decides whether upload runs.
	config.Load()

	rt := hook.NewRuntime(ad)
	rt.Stdin = stdin
	rt.Stdout = stdout
	rt.Stderr = stderr
	rt.Exec = executor.NewReal()
	rt.LogError = AppendError
	rt.UploadEvent = uploaderFactory()

	// Bound the entire invocation by the same cap the runtime would
	// apply internally. Doubling the bound here is intentional: it lets
	// a hung deferred response emit still complete inside the agent's
	// own hook timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*hook.CapHook+1*time.Second)
	defer cancel()

	_ = rt.Run(ctx, aieventc.HookEvent(hookEvent))
	return 0
}

// uploaderFactory is the seam RunHook uses to obtain the upload
// closure. Production points it at newUploader, which reads
// process-wide config and constructs an ingest.Client. Tests override
// it to keep _hook invocations from reaching the real network or
// reading a developer's per-user config.
var uploaderFactory = newUploader

// newUploader builds the per-invocation upload seam used by the hook
// runtime. It returns nil — i.e., upload disabled — whenever enterprise
// config is missing or incomplete; the runtime treats nil as a no-op
// rather than an error, preserving the fail-open contract. When config
// is valid, the returned closure POSTs a single-element batch to the
// AI-agents endpoint and surfaces the transport error to the runtime,
// which logs it to errors.jsonl with the event_id.
func newUploader() func(context.Context, aieventc.Event) error {
	cfg, ok := ingest.Snapshot()
	if !ok {
		return nil
	}
	client, ok := ingest.New(cfg, nil)
	if !ok {
		return nil
	}
	customerID := cfg.CustomerID
	return func(ctx context.Context, ev aieventc.Event) error {
		return client.UploadEvents(ctx, customerID, []aieventc.Event{ev})
	}
}

// adapterForHookAgent maps the `_hook <agent>` argument onto a
// constructed adapter. Returns nil for any unknown agent — the caller
// translates that to an exit-0 fail-open path. Constructed with the
// real user home directory and a self-resolved binary path so any
// adapter behavior that depends on those (e.g., logging the running
// binary) is consistent with what `hooks install` would have written.
func adapterForHookAgent(agent string) adapter.Adapter {
	home, err := os.UserHomeDir()
	if err != nil {
		// No home → adapters that compute settings paths from $HOME
		// would fail. Returning nil here short-circuits to the fail-open
		// path; adapters that don't need home (none today) would still
		// be reachable when one is added.
		return nil
	}
	binaryPath, err := Resolve()
	if err != nil {
		// Self-path resolution failed (e.g., /proc unavailable). The
		// adapter only uses the binary path for ShellCommand outputs,
		// none of which are read on the hot path; an empty string keeps
		// the runtime functional.
		binaryPath = ""
	}
	switch agent {
	case claudecode.AgentName:
		return claudecode.New(home, binaryPath)
	case codex.AgentName:
		return codex.New(home, binaryPath)
	}
	return nil
}
