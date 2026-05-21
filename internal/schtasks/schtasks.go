package schtasks

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const taskName = "StepSecurity Dev Machine Guard"

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

	// For admin installs the log dir lives at C:\ProgramData\StepSecurity, which
	// inherits ACLs from C:\ProgramData and only grants non-admin users
	// Read & Execute on the files inside. The /ru INTERACTIVE task fires under
	// whatever user is logged on — typically a non-admin developer — and
	// cmd.exe's `>>` redirect to agent.log would fail with Access Denied, which
	// aborts the whole task action. Grant BUILTIN\Users (SID 545) Modify rights
	// on the log dir, propagated to files and subfolders, so any logged-in
	// user can append to the log files.
	if exec.IsRoot() {
		_, _, _, icaclsErr := exec.Run(ctx, "icacls", logDir, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/Q")
		if icaclsErr != nil {
			log.Warn("could not adjust log dir ACLs (%v) — non-admin users may not be able to write to %s", icaclsErr, logDir)
		}
	}

	// Bake STEPSECURITY_HOME into the task command. Admin/INTERACTIVE
	// tasks (machine-wide installs) anchor at C:\ProgramData\StepSecurity
	// so the scheduled task and the MSI's earlier write_config agree on
	// the dir, regardless of which interactive user is logged on at fire
	// time. Non-admin tasks track paths.Home() (whatever the user's own
	// install dir resolves to).
	var stepHome string
	if exec.IsRoot() {
		stepHome = `C:\ProgramData\StepSecurity`
	} else {
		stepHome = paths.Home()
	}

	args := buildCreateArgs(binaryPath, logDir, stepHome, hours, exec.IsRoot())
	log.Debug("schtasks create: binary=%q log_dir=%q step_home=%q hours=%d is_admin=%v", binaryPath, logDir, stepHome, hours, exec.IsRoot())

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

func buildCreateArgs(binaryPath, logDir, stepHome string, hours int, isAdmin bool) []string {
	// `set "VAR=value"` is the safe cmd.exe form when the value may
	// contain spaces or `&` / `|` / `<` / `>` metacharacters — without
	// the quotes, cmd.exe would split on the first space and the
	// remainder would be treated as a separate command. Inside the outer
	// `cmd /c "..."` quotes the inner double-quotes are escaped as `""`.
	// stepHome ultimately comes from $HOME (e.g. `C:\Users\John Doe`),
	// so quoting is load-bearing here.
	taskCmd := fmt.Sprintf(`cmd /c "set ""STEPSECURITY_HOME=%s"" && \"%s\" send-telemetry >> \"%s\agent.log\" 2>> \"%s\agent.error.log\""`,
		stepHome, binaryPath, logDir, logDir)
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
