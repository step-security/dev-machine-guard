package schtasks

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const (
	taskName     = "StepSecurity Dev Machine Guard"
	launcherName = "stepsecurity-dev-machine-guard-task.exe"
)

// TaskName is the Windows scheduled task name. Exported so other packages
// (e.g. schedinfo) can query the task without re-deriving the constant.
const TaskName = taskName

// logonTaskName is the companion at-logon task. schtasks /create supports a
// single trigger, so the at-logon catch-up trigger lives in its own task
// alongside the hourly one. Both invoke `send-telemetry`; the singleton lock
// serializes an overlapping logon+hourly fire so they never scan concurrently.
const logonTaskName = taskName + " (Logon)"

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
	hourlyArgs := buildCreateArgs(taskName, taskBinary, stepHome, []string{"/sc", "HOURLY", "/mo", strconv.Itoa(hours)}, exec.IsRoot())
	log.Debug("schtasks create: task_binary=%q agent=%q install_dir=%q hours=%d is_admin=%v", taskBinary, binaryPath, stepHome, hours, exec.IsRoot())

	_, stderr, exitCode, err := exec.Run(ctx, "schtasks", hourlyArgs...)
	log.Debug("schtasks /create %q: exit_code=%d err=%v", taskName, exitCode, err)
	if err != nil {
		return fmt.Errorf("failed to create scheduled task: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to create scheduled task (exit code %d): %s", exitCode, stderr)
	}
	applyBatterySettings(ctx, exec, log, taskName)

	// Companion at-logon task: makes login a catch-up trigger so a device
	// that's been off/asleep scans on next sign-in rather than waiting for the
	// next hourly tick. The singleton lock serializes an overlapping logon+hourly
	// fire. Best-effort — a failure here leaves the hourly schedule fully functional.
	logonArgs := buildCreateArgs(logonTaskName, taskBinary, stepHome, []string{"/sc", "ONLOGON"}, exec.IsRoot())
	if _, lstderr, lexit, lerr := exec.Run(ctx, "schtasks", logonArgs...); lerr != nil || lexit != 0 {
		log.Warn("could not create at-logon catch-up task (%v, exit %d): %s — hourly schedule still active", lerr, lexit, strings.TrimSpace(lstderr))
	} else {
		applyBatterySettings(ctx, exec, log, logonTaskName)
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
	log.Debug("schtasks /delete %q: exit_code=%d err=%v", taskName, exitCode, err)
	if err != nil {
		return fmt.Errorf("failed to delete scheduled task: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("failed to delete scheduled task (exit code %d): %s", exitCode, stderr)
	}

	// Remove the companion at-logon task. Best-effort: it won't exist when
	// upgrading from a version that predates it, and "not found" must not fail
	// the uninstall.
	if _, lstderr, lexit, lerr := exec.Run(ctx, "schtasks", "/delete", "/tn", logonTaskName, "/f"); lerr != nil || lexit != 0 {
		log.Debug("schtasks /delete %q: exit_code=%d err=%v stderr=%q (ignored)", logonTaskName, lexit, lerr, strings.TrimSpace(lstderr))
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

// buildCreateArgs returns the schtasks /create arguments for a scan task
// with the given name and schedule spec (e.g. ["/sc","HOURLY","/mo","4"] or
// ["/sc","ONLOGON"]). The task action invokes the binary directly (no `cmd /c`
// wrapper) — env config and log routing both live in the binary now
// (--install-dir + filelog), and the wrapper was the source of a visible
// cmd.exe flash on every fire.
func buildCreateArgs(name, binaryPath, stepHome string, schedule []string, isAdmin bool) []string {
	taskCmd := fmt.Sprintf(`"%s" send-telemetry --install-dir="%s"`, binaryPath, stepHome)
	args := []string{"/create", "/tn", name, "/tr", taskCmd}
	args = append(args, schedule...)
	args = append(args, "/f")
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

// applyBatterySettings re-imports the named task's XML with the power /
// missed-run / retry settings that `schtasks /create` cannot set from the
// command line: DisallowStartIfOnBatteries=false, StopIfGoingOnBatteries=false,
// StartWhenAvailable=true, and RestartOnFailure (15 min, 3 attempts). The OS
// defaults (battery-restricted, no catch-up, 1-minute retry) otherwise leave a
// laptop on battery silently never firing the task and retry too aggressively.
// Flow: query the task's generated XML, force the Settings, and re-import via
// `schtasks /create /xml`. Pure schtasks.exe — no dependency on the PowerShell
// ScheduledTasks module (absent on Server Core). Best-effort: any failure
// leaves the task with default settings, which is still better than no task.
func applyBatterySettings(ctx context.Context, exec executor.Executor, log *progress.Logger, name string) {
	stdout, stderr, code, err := exec.Run(ctx, "schtasks", "/query", "/tn", name, "/xml")
	if err != nil || code != 0 {
		log.Warn("could not read XML for task %q (%v, exit %d): %s — keeping default battery settings", name, err, code, strings.TrimSpace(stderr))
		return
	}

	patched, changed := patchBatterySettings(decodeTaskXML(stdout))
	if !changed {
		log.Debug("task %q already has the desired battery settings", name)
		return
	}

	tmp, err := os.CreateTemp("", "stepsec-task-*.xml")
	if err != nil {
		log.Warn("could not create temp file to update task %q settings (%v) — keeping defaults", name, err)
		return
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	// schtasks /create /xml is happiest with UTF-16LE+BOM input across Windows
	// versions, which is also what /query /xml emits.
	_, werr := tmp.Write(encodeTaskXMLUTF16(patched))
	_ = tmp.Close()
	if werr != nil {
		log.Warn("could not write temp XML for task %q (%v) — keeping defaults", name, werr)
		return
	}

	if _, rstderr, rcode, rerr := exec.Run(ctx, "schtasks", "/create", "/tn", name, "/xml", tmpPath, "/f"); rerr != nil || rcode != 0 {
		log.Warn("could not re-import task %q with battery settings (%v, exit %d): %s — keeping defaults", name, rerr, rcode, strings.TrimSpace(rstderr))
		return
	}
	log.Debug("applied battery / StartWhenAvailable settings to task %q", name)
}

// retryInterval / retryCount control the on-failure retry: if a scheduled run
// exits non-zero, Task Scheduler retries it after retryInterval, up to
// retryCount times (vs the OS default of 1 minute). PT15M is ISO-8601 for 15
// minutes.
const (
	retryInterval = "PT15M"
	retryCount    = 3
)

// patchBatterySettings forces the power / missed-run settings (battery +
// StartWhenAvailable) and the on-failure retry policy to the values we want,
// inserting any the queried XML omitted. Returns the patched XML and whether
// anything changed. All edits are schema-safe: battery / StartWhenAvailable
// replace existing elements in place; RestartOnFailure is injected last in
// <Settings> (where Task Scheduler itself serializes it), so the result stays
// valid in a single re-import.
func patchBatterySettings(xml string) (string, bool) {
	out := xml
	out = setXMLElement(out, "DisallowStartIfOnBatteries", "false")
	out = setXMLElement(out, "StopIfGoingOnBatteries", "false")
	out = setXMLElement(out, "StartWhenAvailable", "true")
	out = setRestartOnFailure(out, retryInterval, retryCount)
	return out, out != xml
}

// setRestartOnFailure forces <RestartOnFailure><Interval>..</Interval>
// <Count>..</Count></RestartOnFailure> in xml: it replaces an existing block or
// injects one just before </Settings> (RestartOnFailure is the trailing
// settings element in Task Scheduler's own XML, so last is the right spot).
func setRestartOnFailure(xml, interval string, count int) string {
	block := fmt.Sprintf("<RestartOnFailure><Interval>%s</Interval><Count>%d</Count></RestartOnFailure>", interval, count)
	if start := strings.Index(xml, "<RestartOnFailure>"); start >= 0 {
		if rel := strings.Index(xml[start:], "</RestartOnFailure>"); rel >= 0 {
			end := start + rel + len("</RestartOnFailure>")
			return xml[:start] + block + xml[end:]
		}
	}
	if i := strings.Index(xml, "</Settings>"); i >= 0 {
		return xml[:i] + "  " + block + "\n  " + xml[i:]
	}
	return xml
}

// setXMLElement sets <tag>value</tag> in xml: it replaces the element's current
// value if the element is present, otherwise injects the element just before
// </Settings>. Returns xml unchanged only if there's no </Settings> to inject
// into (no recognizable task XML).
func setXMLElement(xml, tag, value string) string {
	open, closeTag := "<"+tag+">", "</"+tag+">"
	if start := strings.Index(xml, open); start >= 0 {
		if rel := strings.Index(xml[start:], closeTag); rel >= 0 {
			end := start + rel + len(closeTag)
			return xml[:start] + open + value + closeTag + xml[end:]
		}
	}
	if i := strings.Index(xml, "</Settings>"); i >= 0 {
		return xml[:i] + "  " + open + value + closeTag + "\n  " + xml[i:]
	}
	return xml
}

// decodeTaskXML converts the bytes emitted by `schtasks /query /xml` to a UTF-8
// string. That output is typically UTF-16LE with a BOM; UTF-8 (with or without
// BOM) and plain ASCII are handled too.
func decodeTaskXML(raw string) string {
	b := []byte(raw)
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE: // UTF-16LE BOM
		u16 := make([]uint16, 0, (len(b)-2)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u16 = append(u16, uint16(b[i])|uint16(b[i+1])<<8)
		}
		return string(utf16.Decode(u16))
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF: // UTF-8 BOM
		return string(b[3:])
	default:
		return raw
	}
}

// encodeTaskXMLUTF16 serializes a UTF-8 string to UTF-16LE with a BOM, the
// form schtasks /create /xml accepts most reliably across Windows versions.
func encodeTaskXMLUTF16(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, 0, 2+len(u16)*2)
	out = append(out, 0xFF, 0xFE) // UTF-16LE BOM
	// AppendUint16 writes low-byte-then-high-byte (UTF-16LE); using the stdlib
	// encoder avoids a manual uint16->byte narrowing that gosec G115 flags.
	for _, u := range u16 {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	return out
}
