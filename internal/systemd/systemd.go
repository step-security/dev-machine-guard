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
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const unitName = "stepsecurity-dev-machine-guard"

// TimerUnitPath returns the per-user systemd timer unit path installed for
// periodic scanning. Exported so the telemetry package's invocation detector
// can stat for an installed footprint without re-deriving the path. Returns
// empty when the home directory cannot be resolved.
func TimerUnitPath() string {
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		return ""
	}
	return filepath.Join(homeDir, ".config", "systemd", "user", unitName+".timer")
}

// ServiceUnitName returns the systemd user service unit name (e.g. for
// `systemctl --user is-active`). Exported so the telemetry invocation detector
// can probe whether the timer-launched service is currently running.
func ServiceUnitName() string { return unitName + ".service" }

// Install configures a systemd user timer for periodic scanning.
// If already installed, upgrades by removing and re-creating the units.
//
// Only `--user` units are supported. Root install would need a system
// unit at /etc/systemd/system/, which has different lifecycle and
// privilege requirements (the timer fires as root, the scanner expects
// per-user search dirs and HOME). Reject early with a clear message
// instead of failing opaquely on `systemctl --user` calls that root
// has no session for.
func Install(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	if exec.IsRoot() {
		return fmt.Errorf("systemd install as root is not supported — run as the target user (system-wide unit deployment will land in a future release)")
	}

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
	logDir := paths.Home()
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}

	unitDir := filepath.Join(homeDir, ".config", "systemd", "user")
	if err := os.MkdirAll(unitDir, 0o755); err != nil {
		return fmt.Errorf("creating systemd user unit directory: %w", err)
	}

	data := unitTemplateData{
		BinaryPath:       systemdEscape(binaryPath),
		LogDir:           systemdEscape(logDir),
		OnCalendar:       onCalendarFor(hours),
		StepSecurityHome: systemdEnvEscape(logDir),
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
	// the singleton lock, so a Persistent=true catch-up cannot race that
	// inline run on the lockfile (issue #62).
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
// may trigger one immediate catch-up scan via the service unit — that's
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
	BinaryPath       string // systemd-escaped (spaces replaced with \x20)
	LogDir           string
	OnCalendar       string
	StepSecurityHome string // baked into Environment= so paths.Home() resolves under timer-invoked runs
}

// systemdEscape escapes a file path for use in systemd unit files.
// Spaces must be escaped as \x20 in ExecStart and related directives.
func systemdEscape(path string) string {
	return strings.ReplaceAll(path, " ", `\x20`)
}

// systemdEnvEscape escapes a value for inclusion inside a double-quoted
// Environment="VAR=value" assignment. systemd treats the quoted span
// as a single token but still honours backslash escaping inside it —
// any literal control character or quote in the value must be escaped
// or the unit file silently parses to garbage (systemd-analyze verify
// catches it; a daemon-reload of a broken unit does not). Per
// systemd.exec(5) the shell-style escapes inside the quoted form are
// \", \\, \n, \r, \t — a raw newline in particular would terminate
// the directive and let any trailing content land as a new top-level
// unit-file line. Filesystem paths contain none of these on the happy
// path, but config.json values are operator-editable (and an attacker
// with write access there shouldn't be able to inject a new directive
// into the generated unit).
//
// Order matters: replace `\` first so the backslashes we introduce for
// the other escapes don't get double-escaped.
func systemdEnvEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	value = strings.ReplaceAll(value, "\r", `\r`)
	value = strings.ReplaceAll(value, "\t", `\t`)
	return value
}

// Environment="VAR=value" with the value-bearing form quoted so paths
// containing spaces (e.g. /opt/Step Security/) survive systemd's
// whitespace splitting. Per systemd.exec(5), the entire "VAR=value" can
// be wrapped in either single or double quotes; we use double quotes
// for consistency with the rest of the unit and only need to worry
// about embedded `"` characters in the value, which would themselves be
// unusual in a filesystem path.
const serviceTmpl = `[Unit]
Description=StepSecurity Dev Machine Guard scan

[Service]
Type=oneshot
ExecStart={{.BinaryPath}} send-telemetry
Environment="STEPSECURITY_HOME={{.StepSecurityHome}}"
StandardOutput=append:{{.LogDir}}/agent.log
StandardError=append:{{.LogDir}}/agent.error.log
`

// onCalendarFor maps the scan interval to a wall-clock OnCalendar=
// expression. Unlike monotonic OnUnitActiveSec, realtime timers honour
// Persistent=true and catch up after suspend/power-off. Mirrors
// schtasks.scheduleFor: under 24h is hourly steps from midnight (a
// non-divisor of 24 leaves a shorter final gap), 24h+ is whole days
// (day-of-month steps reset each month).
func onCalendarFor(hours int) string {
	if hours >= 24 {
		days := min(hours/24, 31)
		if days == 1 {
			return "*-*-* 00:00:00"
		}
		return fmt.Sprintf("*-*-01/%d 00:00:00", days)
	}
	if hours <= 1 {
		return "*-*-* *:00:00"
	}
	return fmt.Sprintf("*-*-* 00/%d:00:00", hours)
}

// The user manager (and so this timer) stops when the user's last session
// ends unless lingering is enabled (loginctl enable-linger). Not enabled
// here: it is a per-user login policy change, and Persistent=true already
// catches up missed runs at next login.
//
// OnBootSec keeps the scan shortly after boot. RandomizedDelaySec spreads
// the fleet off the shared wall-clock boundary.
const timerTmpl = `[Unit]
Description=StepSecurity Dev Machine Guard periodic scan

[Timer]
OnBootSec=5min
OnCalendar={{.OnCalendar}}
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
`
