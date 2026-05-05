package cli

import (
	"context"
	"fmt"

	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter"
	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter/claudecode"
	"github.com/step-security/dev-machine-guard/internal/aiagents/adapter/codex"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// SupportedAgents is the canonical list of agent names accepted by
// `--agent`. Order matters for user-facing diagnostics (the `unsupported
// agent` error lists them in this order) and for the default fan-out
// in selectAdapters.
//
// Adding a new agent means: append here, add a case in adapterForAgent,
// add the constructor case in allAdapters, and add the adapter package.
// No other changes are needed in this layer.
var SupportedAgents = []string{
	claudecode.AgentName,
	codex.AgentName,
}

// adapterForAgent maps an explicit agent name onto a constructed
// adapter. The single CLI seam between the user-facing `--agent` flag
// and the per-agent constructor.
//
// home is the user's home directory (each adapter computes its own
// settings paths from it). binaryPath is the absolute, symlink-resolved
// DMG binary path that adapters embed into the hook command they write
// to settings.
//
// Unsupported agents produce an error that names every supported agent
// so the user does not have to read source to learn the option list.
func adapterForAgent(agent, home, binaryPath string) (adapter.Adapter, error) {
	switch agent {
	case claudecode.AgentName:
		return claudecode.New(home, binaryPath), nil
	case codex.AgentName:
		return codex.New(home, binaryPath), nil
	default:
		return nil, fmt.Errorf("unsupported agent %q (supported: %s, %s)",
			agent, claudecode.AgentName, codex.AgentName)
	}
}

// allAdapters returns every adapter DMG knows about, in the order
// declared by SupportedAgents. Used by selectAdapters when the caller
// did not pin a specific agent so we fan out across whichever agents
// are actually present on disk.
func allAdapters(home, binaryPath string) []adapter.Adapter {
	return []adapter.Adapter{
		claudecode.New(home, binaryPath),
		codex.New(home, binaryPath),
	}
}

// selectAdapters resolves the install/uninstall target list from the
// `--agent` flag:
//
//   - explicit agent: yields exactly that adapter, skipping detection.
//     The user's explicit `--agent claude-code` is an unconditional
//     opt-in — install proceeds even when the agent's CLI is not on
//     $PATH (the user may install it later, or installs it in a
//     non-PATH location and runs DMG from a wrapper).
//
//   - empty agent: runs Detect across every known adapter; only those
//     whose CLI binary `executor.LookPath` resolves are returned.
//     Settings file presence is NOT a gate — the adapter creates its
//     settings file from scratch on first install.
//
// Detect errors abort the whole selection: an unexpected error here
// (e.g. the executor itself broke) should not be silently swallowed
// into "no agents detected". Plain "not on $PATH" results, by
// contrast, are normal and produce Detected=false with a nil error
// from the adapter.
func selectAdapters(ctx context.Context, agent, home, binaryPath string, exec executor.Executor) ([]adapter.Adapter, error) {
	if agent != "" {
		a, err := adapterForAgent(agent, home, binaryPath)
		if err != nil {
			return nil, err
		}
		return []adapter.Adapter{a}, nil
	}
	var detected []adapter.Adapter
	for _, a := range allAdapters(home, binaryPath) {
		res, err := a.Detect(ctx, exec)
		if err != nil {
			return nil, fmt.Errorf("detect %s: %w", a.Name(), err)
		}
		if res.Detected {
			detected = append(detected, a)
		}
	}
	return detected, nil
}
