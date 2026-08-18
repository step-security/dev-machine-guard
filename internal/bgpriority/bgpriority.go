// Package bgpriority moves the current process into the operating system's
// background CPU/IO priority band so telemetry scans never compete with the
// interactive user for disk or CPU. Every mechanism used is throttled-but-
// guaranteed-progress (the tier Time Machine, Spotlight, and defrag run at),
// never an idle-only class that could be starved indefinitely under sustained
// load — so a scan on a busy machine gets slower, not stuck; the existing
// per-phase budgets and scan deadline bound the worst case.
//
// Inheritance: macOS task policy and Linux nice/ioprio are inherited across
// fork/exec, so every subprocess the scan spawns (npm ls, brew, spctl, ...)
// runs in the same band. On Windows, children inherit the below-normal CPU
// class but not the process's background IO mode.
package bgpriority

import (
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// EnvDisable is the per-device escape hatch: set to "1" to keep the scan at
// normal priority (e.g. while timing a scan, or if a fleet's machines are
// dedicated build hosts where nothing interactive competes).
const EnvDisable = "STEPSEC_DISABLE_BACKGROUND_PRIORITY"

// applyImpl is the per-OS implementation; a var so tests can intercept it.
var applyImpl = apply

// Apply lowers the current process (and, where the OS inherits it, its
// children) to background priority. Best-effort by contract: failure to
// apply must never fail the run, so errors are logged and swallowed.
func Apply(exec executor.Executor, log *progress.Logger) {
	if exec.Getenv(EnvDisable) == "1" {
		log.Debug("background priority: disabled via %s", EnvDisable)
		return
	}
	desc, err := applyImpl()
	if err != nil {
		log.Warn("background priority: not applied (%v) — continuing at normal priority", err)
		return
	}
	if desc != "" {
		log.Progress("Running at background priority: %s (disable with %s=1)", desc, EnvDisable)
	}
}
