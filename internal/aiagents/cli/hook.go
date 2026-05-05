// Package cli houses entry points for the AI-agent hooks domain:
// `hooks install`, `hooks uninstall`, and the hidden `_hook` runtime.
//
// The runtime entry point intentionally lives outside internal/cli so the
// hot path can bypass cli.Parse, config.Load, and logger construction —
// agents invoke `_hook` on every event and a non-zero exit is treated as a
// hook failure / block. Fail-open is a hard contract enforced here.
package cli

import "io"

// RunHook is the hidden `_hook <agent> <event>` entry point.
//
// Signature is locked at Phase 0 to avoid churning every test and call site
// when ticket 2.8 wires the real runtime. The 2.8 implementation reads the
// hook payload from stdin (capped at 5 MiB), emits an agent-allow response
// on stdout, and treats any error as fail-open.
//
// Contract (enforced by hook_test.go and main_test.go):
//   - returns 0 on every code path, including malformed args, unknown agents,
//     unparseable stdin, and internal panics
//   - writes nothing to stdout unless emitting a valid agent-allow response
//   - writes nothing to stderr on the success path
//
// Phase 0 ships a stub that always returns 0 and writes nothing.
//
// args is os.Args[2:] — i.e., everything after the `_hook` verb.
func RunHook(stdin io.Reader, stdout, stderr io.Writer, args []string) int {
	_ = stdin
	_ = stdout
	_ = stderr
	_ = args
	return 0
}
