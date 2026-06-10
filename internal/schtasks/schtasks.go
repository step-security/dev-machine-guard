package schtasks

import (
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const (
	taskName     = "StepSecurity Dev Machine Guard"
	launcherName = "stepsecurity-dev-machine-guard-task.exe"
)

// IsTaskRegistered reports whether the Windows scheduled task created by
// `dev-machine-guard install` is currently registered. Used by the
// telemetry package's invocation detector to distinguish a manual CLI run
// from a scheduler-triggered one. Any error or non-zero schtasks exit is
// treated as "not registered" so a transient Schedule-service hiccup
// degrades to "one_time" rather than erroring the run.
func IsTaskRegistered() bool {
	cmd := osexec.Command("schtasks", "/query", "/tn", taskName)
	return cmd.Run() == nil
}

// Install configures Windows Task Scheduler for periodic scanning.
// If already installed, upgrades by removing and re-creating the task.
func Install(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	// Check for existing installation and upgrade
	if isConfigured(ctx, exec) {
		log.Progress("Existing agent installation detected. Upgrading...")
		if err := doUninstall(ctx, exec, log); err != nil {
			log.Warn("failed to remove previous scheduled task: %v — continuing install anyway", err)
		}
		log.Progress("Previous installation removed. Installing new version...")
	}

	binaryPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determining binary path: %w", err)
	}

	hours, _ := strconv.Atoi(config.ScanFrequencyHours)
	if hours <= 0 {
		hours = 4
	}

	logDir := resolveLogDir(exec)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	// For admin installs the log dir lives at C:\ProgramData\StepSecurity,
	// which inherits ACLs from C:\ProgramData and only grants non-admin
	// users Read & Execute. The /ru INTERACTIVE task fires under the
	// logged-in user (typically non-admin), and the agent's filelog
	// opens agent.error.log here in append mode — that needs write
	// access. Grant BUILTIN\Users (SID 545) Modify rights on the dir,
	// propagated to files and subfolders.
	if exec.IsRoot() {
		_, _, _, icaclsErr := exec.Run(ctx, "icacls", logDir, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/Q")
		if icaclsErr != nil {
			log.Warn("could not adjust log dir ACLs (%v) — non-admin users may not be able to write to %s", icaclsErr, logDir)
		}
	}

	// Pass --install-dir to the task command. logDir already carries the
	// canonical resolution (admin → C:\ProgramData\StepSecurity,
	// non-admin → paths.Home() with a CurrentUser fallback, finally
	// ProgramData) so we reuse it as STEPSECURITY_HOME. Using paths.Home()
	// directly here would emit --install-dir="" when HOME/USERPROFILE
	// aren't resolvable, which the CLI treats as an explicit opt-out
	// (disables file logging).
	stepHome := logDir

	taskBinary := resolveTaskBinary(exec, binaryPath)
	args := buildCreateArgs(taskBinary, stepHome, hours, exec.IsRoot())
	log.Debug("schtasks create: task_binary=%q agent=%q install_dir=%q hours=%d is_admin=%v", taskBinary, binaryPath, stepHome, hours, exec.IsRoot())

	_, stderr, exitCode, err := exec.Run(ctx, "schtasks", args...)
	log.Debug("schtasks /create: exit_code=%d err=%v", exitCode, err)
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to create scheduled task (exit code %d): %s", exitCode, stderr)
	}

	log.Progress("Windows Task Scheduler configuration completed successfully")
	log.Progress("  Task: %s", taskName)
	log.Progress("  Logs: %s\\agent.log", logDir)
	log.Progress("Installation complete!")
	log.Progress("The agent will now run automatically every %d hours", hours)

	return nil
}

// RunNow asks Task Scheduler to fire the registered task immediately,
// using its configured principal (/ru INTERACTIVE for admin installs).
// Used by the install flow under LocalSystem to surface first-run
// telemetry under the logged-in user rather than scanning SYSTEM's
// empty profile inline.
//
// schtasks /run returns 0 once the scheduler has accepted the request;
// it does not wait for the task to complete and does not report whether
// an interactive session exists. If no user is logged in, the trigger
// silently no-ops and the task fires on its next hourly tick.
func RunNow(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()
	_, stderr, exitCode, err := exec.Run(ctx, "schtasks", "/run", "/tn", taskName)
	log.Debug("schtasks /run: exit_code=%d err=%v", exitCode, err)
	if err != nil {
		return fmt.Errorf("failed to trigger scheduled task: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to trigger scheduled task (exit code %d): %s", exitCode, stderr)
	}
	log.Progress("Triggered initial scan under the logged-in user")
	return nil
}

// Uninstall removes the scheduled task.
func Uninstall(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	if !isConfigured(ctx, exec) {
		log.Progress("Agent is not currently configured for periodic execution")
		return nil
	}

	return doUninstall(ctx, exec, log)
}

func doUninstall(ctx context.Context, exec executor.Executor, log *progress.Logger) error {
	_, stderr, exitCode, err := exec.Run(ctx, "schtasks", "/delete", "/tn", taskName, "/f")
	log.Debug("schtasks /delete: exit_code=%d err=%v", exitCode, err)
	if err != nil {
		return fmt.Errorf("failed to delete scheduled task: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to delete scheduled task (exit code %d): %s", exitCode, stderr)
	}

	log.Progress("Removed scheduled task: %s", taskName)
	log.Progress("Windows Task Scheduler configuration removed successfully")
	return nil
}

func isConfigured(ctx context.Context, exec executor.Executor) bool {
	_, _, exitCode, _ := exec.Run(ctx, "schtasks", "/query", "/tn", taskName)
	return exitCode == 0
}

// resolveTaskBinary returns the path the scheduled task should invoke.
// When the GUI-subsystem launcher sits next to the agent (MSI install
// layout), the task points at it so Windows doesn't allocate a console
// for the agent under /ru INTERACTIVE. When the launcher isn't present
// (ad-hoc deploys of just the agent .exe), we fall back to the agent
// directly — subprocess flashes are still suppressed via winproc, only
// the agent's own console-flash mitigation is forfeited.
func resolveTaskBinary(exec executor.Executor, agentPath string) string {
	launcher := filepath.Join(filepath.Dir(agentPath), launcherName)
	if exec.FileExists(launcher) {
		return launcher
	}
	return agentPath
}

// buildCreateArgs returns the schtasks /create arguments for the
// periodic scan task. The task action invokes the binary directly
// (no `cmd /c` wrapper) — env config and log routing both live in
// the binary now (--install-dir + filelog), and the wrapper was the
// source of a visible cmd.exe flash on every fire.
func buildCreateArgs(binaryPath, stepHome string, hours int, isAdmin bool) []string {
	taskCmd := fmt.Sprintf(`"%s" send-telemetry --install-dir="%s"`, binaryPath, stepHome)
	args := []string{"/create", "/tn", taskName, "/tr", taskCmd,
		"/sc", "HOURLY", "/mo", strconv.Itoa(hours), "/f"}
	if isAdmin {
		// /ru INTERACTIVE binds the task to the NT AUTHORITY\INTERACTIVE
		// well-known group (SID S-1-5-4) so it fires under the security
		// context of whoever is interactively logged on at trigger time —
		// picking up their HKCU, %USERPROFILE%, and PATH. /ru SYSTEM would
		// run as NT AUTHORITY\SYSTEM, which can't see any of the user-scoped
		// data the scanner depends on.
		args = append(args, "/ru", "INTERACTIVE")
	}
	return args
}

func resolveLogDir(exec executor.Executor) string {
	if exec.IsRoot() {
		return `C:\ProgramData\StepSecurity`
	}
	if dir := paths.Home(); dir != "" {
		return dir
	}
	// paths.Home() resolves $HOME via os.UserHomeDir, which can fail on
	// systems where HOME/USERPROFILE aren't set; fall back to the
	// executor's known-good lookup before resorting to ProgramData.
	homeDir, _ := exec.CurrentUser()
	if homeDir != nil {
		return homeDir.HomeDir + `\.stepsecurity`
	}
	return `C:\ProgramData\StepSecurity`
}
