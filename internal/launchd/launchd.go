package launchd

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// plistEscape XML-escapes a string for use inside a plist <string>
// element. Without this, a path containing &, <, >, ', or " would
// produce malformed XML that launchctl rejects with an opaque parse
// error at load time. text/template's raw substitution does no
// escaping by default — html/template would over-escape unrelated
// content — so we route every templated value through this helper.
func plistEscape(s string) string {
	var sb strings.Builder
	_ = xml.EscapeText(&sb, []byte(s))
	return sb.String()
}

const (
	label           = "com.stepsecurity.agent"
	daemonPlistPath = "/Library/LaunchDaemons/com.stepsecurity.agent.plist"
	systemLogDir    = "/var/log/stepsecurity"
)

// DaemonPlistPath is the system-wide launchd plist installed when the agent
// runs as root. Exported so other packages (notably telemetry's invocation
// detector) can check for an installed footprint without re-deriving the path.
const DaemonPlistPath = daemonPlistPath

// Label is the launchd job label for the agent. Exported so other packages
// (e.g. schedinfo) can address the job without re-deriving the constant.
const Label = label

// DomainTarget returns the launchd domain and the domain/label service target
// for the current privilege level: the system domain for a root LaunchDaemon,
// gui/<uid> for a per-user LaunchAgent. Single source of truth for the domain
// math reused by Install/Uninstall and the scheduler-info collector.
func DomainTarget(exec executor.Executor) (domain, target string) {
	domain = "system"
	if !exec.IsRoot() {
		domain = fmt.Sprintf("gui/%d", os.Getuid())
	}
	return domain, domain + "/" + label
}

// UserPlistPath returns the per-user launchd plist path installed when the
// agent runs without root. Empty when the home directory cannot be resolved.
func UserPlistPath() string {
	return agentPlistPath()
}

func agentPlistPath() string {
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" {
		return ""
	}
	return homeDir + "/Library/LaunchAgents/com.stepsecurity.agent.plist"
}

// Install configures launchd for periodic scanning and loads the job
// (upgrading in place if already installed). With RunAtLoad=true, loading the
// job triggers the run immediately — so this load IS the initial scan and the
// install command deliberately does NOT scan inline on macOS (see main.go).
// Doing both would double-scan at install: once inline, once at load, with the
// second blocked on the singleton lock.
func Install(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	// Check for existing installation and upgrade
	if isConfigured(ctx, exec) {
		log.Progress("Existing agent installation detected. Upgrading...")
		if err := doUninstall(ctx, exec, log); err != nil {
			log.Warn("failed to remove previous launchd installation: %v — continuing install anyway", err)
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
	intervalSeconds := hours * 3600

	plistPath := daemonPlistPath
	logDir := systemLogDir

	// Non-root LaunchAgent: log dir follows the configured install dir
	// (defaults to ~/.stepsecurity). The plist will also bake
	// STEPSECURITY_HOME so scheduler-invoked runs of the binary land in
	// the same place. Root LaunchDaemon stays on the system path
	// (/var/log/stepsecurity) — service-mode root daemons are a
	// well-known macOS convention and we don't reroute them yet.
	if !exec.IsRoot() {
		plistPath = agentPlistPath()
		logDir = paths.Home()
	}

	// Ensure directories exist
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fmt.Errorf("creating log directory: %w", err)
	}
	if !exec.IsRoot() {
		homeDir, _ := os.UserHomeDir()
		if err := os.MkdirAll(homeDir+"/Library/LaunchAgents", 0o755); err != nil {
			return fmt.Errorf("creating LaunchAgents directory: %w", err)
		}
	}

	// Resolve a usable home directory for the plist.
	// When running as root (LaunchDaemon), launchd provides a minimal
	// environment without HOME, so os.UserHomeDir() would fail at runtime.
	// Prefer the GUI console user's HOME; if that lookup fails (no console
	// user — LoggedInUser returns an error per issue #63) fall back to
	// CurrentUser so the plist still has a value to bake in.
	userHome := ""
	if exec.IsRoot() {
		if u, err := exec.LoggedInUser(); err == nil {
			userHome = u.HomeDir
		} else if u, err := exec.CurrentUser(); err == nil {
			userHome = u.HomeDir
		}
	}

	// StepSecurityHome is baked into the plist so when launchd invokes
	// the binary on its own schedule, paths.Home() resolves to the same
	// directory the operator configured at install time — without
	// depending on config.json or the operator's shell environment.
	// Empty when paths.Home() can't resolve (no $HOME for root daemons,
	// say); the binary then falls back through its own resolution chain.
	stepHome := ""
	if !exec.IsRoot() {
		stepHome = paths.Home()
	}

	// Generate plist. Every <string>-bound value is XML-escaped so a
	// path with &, <, >, ', or " produces a well-formed plist that
	// launchctl can actually load. IntervalSeconds is an integer, no
	// escape needed; Label is a fixed constant.
	plistData := plistTemplateData{
		Label:            label,
		BinaryPath:       plistEscape(binaryPath),
		IntervalSeconds:  intervalSeconds,
		LogDir:           plistEscape(logDir),
		UserHome:         plistEscape(userHome),
		StepSecurityHome: plistEscape(stepHome),
	}

	f, err := os.Create(plistPath)
	if err != nil {
		return fmt.Errorf("creating plist file: %w", err)
	}
	defer func() { _ = f.Close() }()

	tmpl, err := template.New("plist").Parse(plistTmpl)
	if err != nil {
		return fmt.Errorf("parsing plist template: %w", err)
	}
	if err := tmpl.Execute(f, plistData); err != nil {
		return fmt.Errorf("writing plist: %w", err)
	}

	if exec.IsRoot() {
		_ = os.Chmod(plistPath, 0o644)
	}

	log.Debug("launchd install: plist=%q log_dir=%q interval=%ds user_home=%q is_root=%v", plistPath, logDir, intervalSeconds, userHome, exec.IsRoot())

	// Bootstrap the plist into its launchd domain. With RunAtLoad=true this
	// runs the job immediately, so this load IS the initial scan — the install
	// command does NOT scan inline on macOS (that would double-scan: once
	// inline, once at load, the second blocked on the singleton lock). The scan
	// runs under the user's GUI session and logs to agent.log. Apple recommends
	// bootstrap/bootout over the deprecated load/unload verbs; root daemons live
	// in the `system` domain, user LaunchAgents in `gui/<uid>` — see DomainTarget.
	domain, _ := DomainTarget(exec)
	_, stderr, exitCode, err := exec.Run(ctx, "launchctl", "bootstrap", domain, plistPath)
	log.Debug("launchctl bootstrap %q %q: exit_code=%d err=%v stderr=%q", domain, plistPath, exitCode, err, stderr)
	if err != nil {
		return fmt.Errorf("launchctl bootstrap failed: %w", err)
	}
	if exitCode != 0 {
		return fmt.Errorf("launchctl bootstrap failed (exit code %d): %s", exitCode, strings.TrimSpace(stderr))
	}

	log.Progress("launchd configuration completed successfully")
	log.Progress("  Plist: %s", plistPath)
	log.Progress("  Logs: %s/agent.log", logDir)
	log.Progress("The agent will run now (via launchd) and then every %d hours, plus at login", hours)

	return nil
}

// Uninstall removes the launchd configuration.
func Uninstall(exec executor.Executor, log *progress.Logger) error {
	ctx := context.Background()

	if !isConfigured(ctx, exec) {
		log.Progress("Agent is not currently configured for periodic execution")
		return nil
	}

	return doUninstall(ctx, exec, log)
}

func doUninstall(ctx context.Context, exec executor.Executor, log *progress.Logger) error {
	plistPath := daemonPlistPath
	if !exec.IsRoot() {
		plistPath = agentPlistPath()
	}

	// Bootout. `bootout` removes a service from its domain regardless of
	// how it was originally added, so it works on plists previously
	// `launchctl load`-ed by older agent versions during upgrade.
	stdout, _, _, _ := exec.Run(ctx, "launchctl", "list")
	if strings.Contains(stdout, label) {
		domain := "system"
		if !exec.IsRoot() {
			domain = fmt.Sprintf("gui/%d", os.Getuid())
		}
		target := domain + "/" + label
		_, stderr, exitCode, err := exec.Run(ctx, "launchctl", "bootout", target)
		log.Debug("launchctl bootout %q: exit_code=%d err=%v stderr=%q", target, exitCode, err, stderr)
		switch {
		case err != nil:
			log.Warn("launchctl bootout failed: %v — the running service may persist until reboot; plist will still be removed", err)
		case exitCode != 0:
			log.Warn("launchctl bootout failed (exit code %d): %s — the running service may persist until reboot; plist will still be removed", exitCode, strings.TrimSpace(stderr))
		default:
			log.Progress("Unloaded launchd agent")
		}
	}

	// Remove plist
	if exec.FileExists(plistPath) {
		_ = os.Remove(plistPath)
		log.Progress("Removed plist file: %s", plistPath)
	}

	log.Progress("launchd configuration removed successfully")
	return nil
}

func isConfigured(ctx context.Context, exec executor.Executor) bool {
	plistPath := daemonPlistPath
	if !exec.IsRoot() {
		plistPath = agentPlistPath()
	}

	if !exec.FileExists(plistPath) {
		return false
	}

	stdout, _, _, _ := exec.Run(ctx, "launchctl", "list")
	return strings.Contains(stdout, label)
}

type plistTemplateData struct {
	Label            string
	BinaryPath       string
	IntervalSeconds  int
	LogDir           string
	UserHome         string // non-empty when running as root; baked into plist as HOME env var
	StepSecurityHome string // non-empty for LaunchAgent; sets STEPSECURITY_HOME so paths.Home() matches install-time choice
}

const plistTmpl = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{.Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.BinaryPath}}</string>
        <string>send-telemetry</string>
    </array>
    <key>StartInterval</key>
    <integer>{{.IntervalSeconds}}</integer>
    <key>RunAtLoad</key>
    <true/>{{if or .UserHome .StepSecurityHome}}
    <key>EnvironmentVariables</key>
    <dict>{{if .UserHome}}
        <key>HOME</key>
        <string>{{.UserHome}}</string>{{end}}{{if .StepSecurityHome}}
        <key>STEPSECURITY_HOME</key>
        <string>{{.StepSecurityHome}}</string>{{end}}
    </dict>{{end}}
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/agent.error.log</string>
</dict>
</plist>
`
