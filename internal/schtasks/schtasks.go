package schtasks

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
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
			log.Progress("Warning: failed to remove previous installation: %v", err)
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

	args := buildCreateArgs(binaryPath, logDir, hours, exec.IsRoot())

	_, stderr, exitCode, err := exec.Run(ctx, "schtasks", args...)
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

func buildCreateArgs(binaryPath, logDir string, hours int, isAdmin bool) []string {
	taskCmd := fmt.Sprintf(`cmd /c "\"%s\" send-telemetry >> \"%s\agent.log\" 2>> \"%s\agent.error.log\""`,
		binaryPath, logDir, logDir)
	args := []string{"/create", "/tn", taskName, "/tr", taskCmd,
		"/sc", "HOURLY", "/mo", strconv.Itoa(hours), "/f"}
	if isAdmin {
		args = append(args, "/ru", "SYSTEM")
	}
	return args
}

func resolveLogDir(exec executor.Executor) string {
	if exec.IsRoot() {
		return `C:\ProgramData\StepSecurity`
	}
	homeDir, _ := exec.CurrentUser()
	if homeDir != nil {
		return homeDir.HomeDir + `\.stepsecurity`
	}
	return `C:\ProgramData\StepSecurity`
}
