package systemd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const unitName = "stepsecurity-dev-machine-guard"

// Install configures a systemd user timer for periodic scanning.
// If already installed, upgrades by removing and re-creating the units.
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

	homeDir, _ := os.UserHomeDir()
	logDir := filepath.Join(homeDir, ".stepsecurity")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	unitDir := filepath.Join(homeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return fmt.Errorf("creating systemd user unit directory: %w", err)
	}

	data := unitTemplateData{
		BinaryPath: systemdEscape(binaryPath),
		LogDir:     systemdEscape(logDir),
		Hours:      hours,
	}

	// Write service unit
	servicePath := filepath.Join(unitDir, unitName+".service")
	if err := writeTemplate(servicePath, serviceTmpl, data); err != nil {
		return fmt.Errorf("writing service unit: %w", err)
	}

	// Write timer unit
	timerPath := filepath.Join(unitDir, unitName+".timer")
	if err := writeTemplate(timerPath, timerTmpl, data); err != nil {
		return fmt.Errorf("writing timer unit: %w", err)
	}

	// Reload and enable
	_, daemonStderr, daemonExitCode, err := exec.Run(ctx, "systemctl", "--user", "daemon-reload")
	if err != nil {
		return fmt.Errorf("daemon-reload failed: %w", err)
	}
	if daemonExitCode != 0 {
		return fmt.Errorf("daemon-reload failed (exit code %d): %s", daemonExitCode, daemonStderr)
	}

	// Enable (without --now) so the unit is loaded across reboots. Activating
	// the timer in this session is deferred to StartTimer, which the install
	// command calls only after its inline post-install telemetry has released
	// the singleton lock. If we used --now here, the timer's Persistent=true +
	// already-elapsed OnBootSec would fire the service immediately and race
	// with that inline run on the lockfile (issue #62).
	_, stderr, exitCode, err := exec.Run(ctx, "systemctl", "--user", "enable", unitName+".timer")
	if err != nil {
		return fmt.Errorf("failed to enable timer: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to enable timer (exit code %d): %s", exitCode, stderr)
	}

	log.Progress("systemd user timer configuration completed successfully")
	log.Progress("  Service: %s", servicePath)
	log.Progress("  Timer:   %s", timerPath)
	log.Progress("  Logs:    %s/agent.log", logDir)
	log.Progress("Installation complete!")
	log.Progress("The agent will now run automatically every %d hours", hours)

	return nil
}

// StartTimer activates the timer that Install enabled. Split out from Install
// so the install command can run its inline post-install telemetry first
// (and release the singleton lock) before the timer is allowed to fire its
// own first invocation. With Persistent=true on the timer unit, this start
// will trigger one immediate catch-up scan via the service unit — that's
// fine because the inline scan has already completed.
func StartTimer(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	_, stderr, exitCode, err := exec.Run(ctx, "systemctl", "--user", "start", unitName+".timer")
	if err != nil {
		return fmt.Errorf("failed to start timer: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to start timer (exit code %d): %s", exitCode, stderr)
	}

	log.Progress("Timer started")
	return nil
}

// Uninstall removes the systemd user timer and service units.
func Uninstall(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	if !isConfigured(ctx, exec) {
		log.Progress("Agent is not currently configured for periodic execution")
		return nil
	}

	return doUninstall(ctx, exec, log)
}

func doUninstall(ctx context.Context, exec executor.Executor, log *progress.Logger) error {
	// Disable and stop the timer
	_, _, _, _ = exec.Run(ctx, "systemctl", "--user", "disable", "--now", unitName+".timer")
	log.Progress("Disabled systemd timer")

	// Stop the service if running
	_, _, _, _ = exec.Run(ctx, "systemctl", "--user", "stop", unitName+".service")

	// Remove unit files
	homeDir, _ := os.UserHomeDir()
	unitDir := filepath.Join(homeDir, ".config", "systemd", "user")
	for _, suffix := range []string{".service", ".timer"} {
		unitPath := filepath.Join(unitDir, unitName+suffix)
		if err := os.Remove(unitPath); err == nil {
			log.Progress("Removed %s", unitPath)
		}
	}

	// Reload
	_, _, _, _ = exec.Run(ctx, "systemctl", "--user", "daemon-reload")

	log.Progress("systemd configuration removed successfully")
	return nil
}

func isConfigured(ctx context.Context, exec executor.Executor) bool {
	stdout, _, _, _ := exec.Run(ctx, "systemctl", "--user", "list-timers", "--no-pager")
	return strings.Contains(stdout, unitName)
}

func writeTemplate(path, tmplStr string, data unitTemplateData) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	tmpl, err := template.New("unit").Parse(tmplStr)
	if err != nil {
		return err
	}
	return tmpl.Execute(f, data)
}

type unitTemplateData struct {
	BinaryPath string // systemd-escaped (spaces replaced with \x20)
	LogDir     string
	Hours      int
}

// systemdEscape escapes a file path for use in systemd unit files.
// Spaces must be escaped as \x20 in ExecStart and related directives.
func systemdEscape(path string) string {
	return strings.ReplaceAll(path, " ", `\x20`)
}

const serviceTmpl = `[Unit]
Description=StepSecurity Dev Machine Guard scan

[Service]
Type=oneshot
ExecStart={{.BinaryPath}} send-telemetry
StandardOutput=append:{{.LogDir}}/agent.log
StandardError=append:{{.LogDir}}/agent.error.log
`

const timerTmpl = `[Unit]
Description=StepSecurity Dev Machine Guard periodic scan

[Timer]
OnBootSec=5min
OnUnitActiveSec={{.Hours}}h
Persistent=true

[Install]
WantedBy=timers.target
`
