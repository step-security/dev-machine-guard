// Package launcher resolves the child process the GUI-subsystem
// launcher (cmd/stepsecurity-dev-machine-guard-task) should spawn for a
// given invocation. The launcher itself lives in cmd/ and is Windows-only
// because it depends on Job Objects and CREATE_NO_WINDOW; the resolution
// logic is platform-agnostic and lives here so it can be unit-tested on
// the macOS CI runners that drive the rest of the test suite.
package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	// AgentBinary is the default child the launcher invokes when no
	// --exec flag is present. Sits next to the launcher in the install
	// directory (MSI: C:\Program Files\StepSecurity\, PowerShell:
	// %USERPROFILE%\.stepsecurity\bin\).
	AgentBinary = "stepsecurity-dev-machine-guard.exe"

	// ExecFlag opts into the generic-target launch mode used by the
	// PowerShell loader. See ResolveTarget for the contract.
	ExecFlag = "--exec"
)

// ResolveTarget returns the child executable's absolute path and the
// argv slice to forward to it, derived from the launcher's own argv
// (i.e. os.Args[1:], not including the program name).
//
// Two modes, dispatched on the first argument:
//
//   - "--exec" mode. argv begins with --exec; the next element is the
//     child binary (resolved via exec.LookPath so bare basenames like
//     "powershell.exe" are accepted alongside fully-qualified paths),
//     and the rest of argv is forwarded to it. Used by the PowerShell
//     loader's scheduled task to wrap `powershell.exe -File loader.ps1
//     send-telemetry` under the launcher's no-console envelope.
//
//   - Default (legacy / MSI) mode. argv does not begin with --exec; the
//     child is the sibling AgentBinary in the launcher's own directory,
//     and all of argv is forwarded to it. Preserves byte-for-byte
//     compatibility with the launcher's pre-1.11.5 behaviour, which is
//     what the MSI install layout's scheduled task action uses.
//
// Errors (all returned from this function; the caller in cmd/.../main.go
// is responsible for mapping them to exit codes + stderr output per the
// contract below):
//
//   - --exec without a target: malformed task action.
//   - --exec target not on PATH: visible at install time rather than
//     silently exiting.
//   - Default mode with no sibling agent: most commonly indicates the
//     launcher was deployed without its companion.
//
// The launcher entrypoint distinguishes the two error contexts:
// --exec errors are written to stderr and the process exits 2, while
// default-mode errors stay silent and exit 1 (preserving byte-for-byte
// compatibility with the pre-1.11.5 launcher that MSI installs rely on).
func ResolveTarget(argv []string) (string, []string, error) {
	if len(argv) > 0 && argv[0] == ExecFlag {
		if len(argv) < 2 {
			return "", nil, fmt.Errorf("%s requires a target executable", ExecFlag)
		}
		target, err := exec.LookPath(argv[1])
		if err != nil {
			return "", nil, fmt.Errorf("%s: cannot resolve %q: %w", ExecFlag, argv[1], err)
		}
		return target, argv[2:], nil
	}

	me, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	agent := filepath.Join(filepath.Dir(me), AgentBinary)
	if _, err := os.Stat(agent); err != nil {
		return "", nil, err
	}
	return agent, argv, nil
}
