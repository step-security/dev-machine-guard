package launchd

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const (
	label           = "com.stepsecurity.agent"
	daemonPlistPath = "/Library/LaunchDaemons/com.stepsecurity.agent.plist"
	systemLogDir    = "/var/log/stepsecurity"
)

func agentPlistPath() string {
	homeDir, _ := os.UserHomeDir()
	return homeDir + "/Library/LaunchAgents/com.stepsecurity.agent.plist"
}

// Install configures launchd for periodic scanning. If already installed, upgrades.
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
	intervalSeconds := hours * 3600

	plistPath := daemonPlistPath
	logDir := systemLogDir

	if !exec.IsRoot() {
		plistPath = agentPlistPath()
		homeDir, _ := os.UserHomeDir()
		logDir = homeDir + "/.stepsecurity"
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

	// Generate plist
	plistData := plistTemplateData{
		Label:           label,
		BinaryPath:      binaryPath,
		IntervalSeconds: intervalSeconds,
		LogDir:          logDir,
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

	// Load plist
	_, _, exitCode, err := exec.Run(ctx, "launchctl", "load", plistPath)
	if err != nil || exitCode != 0 {
		return fmt.Errorf("failed to load launchd configuration")
	}

	log.Progress("launchd configuration completed successfully")
	log.Progress("  Plist: %s", plistPath)
	log.Progress("  Logs: %s/agent.log", logDir)
	log.Progress("Installation complete!")
	log.Progress("The agent will now run automatically every %d hours", hours)

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

	// Unload
	stdout, _, _, _ := exec.Run(ctx, "launchctl", "list")
	if strings.Contains(stdout, label) {
		_, _, _, _ = exec.Run(ctx, "launchctl", "unload", plistPath)
		log.Progress("Unloaded launchd agent")
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
	Label           string
	BinaryPath      string
	IntervalSeconds int
	LogDir          string
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
    <false/>
    <key>StandardOutPath</key>
    <string>{{.LogDir}}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>{{.LogDir}}/agent.error.log</string>
</dict>
</plist>
`
