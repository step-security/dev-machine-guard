package detector

import (
	"context"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/execguard"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/versionmeta"
)

type frameworkSpec struct {
	Name        string
	BinaryName  string
	ProcessName string

	// GUIApp marks a binary that is the desktop app itself rather than a CLI,
	// suppressing the --version exec fallback in getVersion: with no on-disk
	// source the tool reports "unknown" instead of being launched.
	//
	// A packaged Electron app does not implement --version (only the
	// unpackaged `electron` binary's default_app does), so the flag is ignored
	// and the app boots — reported by an Ubuntu 22.04 customer whose scan
	// opened LM Studio's window.
	GUIApp bool
}

var frameworkDefinitions = []frameworkSpec{
	{Name: "ollama", BinaryName: "ollama", ProcessName: "ollama"},
	{Name: "localai", BinaryName: "local-ai", ProcessName: "local-ai"},
	// `lm-studio` is the desktop app's launcher; the CLI is a separate binary, `lms`.
	{Name: "lm-studio", BinaryName: "lm-studio", ProcessName: "lm-studio", GUIApp: true},
	{Name: "text-generation-webui", BinaryName: "textgen", ProcessName: "textgen"},
}

// FrameworkDetector detects AI frameworks and runtimes.
type FrameworkDetector struct {
	exec executor.Executor
	log  *progress.Logger
}

func NewFrameworkDetector(exec executor.Executor) *FrameworkDetector {
	return &FrameworkDetector{exec: exec, log: progress.NewNoop()}
}

// WithLogger injects a logger (used to surface exec fallbacks when metadata
// version resolution misses). Chainable, mirrors configaudit's WithSkipper.
func (d *FrameworkDetector) WithLogger(log *progress.Logger) *FrameworkDetector {
	if log != nil {
		d.log = log
	}
	return d
}

func (d *FrameworkDetector) Detect(ctx context.Context) []model.AITool {
	var results []model.AITool

	for _, spec := range frameworkDefinitions {
		binaryPath, err := d.exec.LookPath(spec.BinaryName)
		if err != nil {
			continue
		}

		version := d.getVersion(ctx, spec, binaryPath)
		isRunning := isProcessRunning(ctx, d.exec, spec.ProcessName)

		results = append(results, model.AITool{
			Name:       spec.Name,
			Vendor:     "Unknown",
			Type:       "framework",
			Version:    version,
			BinaryPath: binaryPath,
			IsRunning:  &isRunning,
		})
	}

	// LM Studio as a GUI application
	if tool, ok := d.detectLMStudioApp(ctx); ok {
		// Avoid duplicating if already found via binary
		found := false
		for _, r := range results {
			if r.Name == "lm-studio" {
				found = true
				break
			}
		}
		if !found {
			results = append(results, tool)
		}
	}

	return results
}

func (d *FrameworkDetector) getVersion(ctx context.Context, spec frameworkSpec, binaryPath string) string {
	// Static-first, exec-last (AGENTS.md §3.4). Bonus: skipping exec also
	// avoids the daemon-warning-decorated output some frameworks (ollama)
	// prepend to --version.
	if v := versionmeta.FromBinary(ctx, d.exec, binaryPath); v != "" {
		return v
	}
	// No exec step for a GUI app: "unknown" is the floor (§3.4), and the tool
	// is still reported as installed.
	if spec.GUIApp {
		d.log.Debug("skipping %s version probe: GUI application, --version would launch it", binaryPath)
		return "unknown"
	}
	if !execguard.SafeToExec(ctx, d.exec, binaryPath) {
		d.log.Warn("skipping %s version probe: quarantined and rejected by Gatekeeper", binaryPath)
		return "unknown"
	}
	d.log.Progress("exec fallback: running %s --version (no metadata version source)", binaryPath)
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binaryPath, "--version")
	if err != nil {
		return "unknown"
	}
	return extractVersionFromOutput(stdout)
}

func (d *FrameworkDetector) detectLMStudioApp(ctx context.Context) (model.AITool, bool) {
	var appPath, version string

	switch d.exec.GOOS() {
	case model.PlatformWindows:
		localAppData := d.exec.Getenv("LOCALAPPDATA")
		appPath = filepath.Join(localAppData, "Programs", "LM Studio")
		if !d.exec.DirExists(appPath) {
			return model.AITool{}, false
		}
		version = readRegistryVersion(ctx, d.exec, "LM Studio")
	case model.PlatformDarwin:
		appPath = "/Applications/LM Studio.app"
		if !d.exec.DirExists(appPath) {
			return model.AITool{}, false
		}
		version = readPlistVersion(ctx, d.exec, filepath.Join(appPath, "Contents", "Info.plist"))
	default: // linux — check common install locations
		homeDir := getHomeDir(d.exec)
		for _, candidate := range []string{
			filepath.Join(homeDir, ".local", "share", "LM Studio"),
			// electron-builder's .deb installs to /opt/<productName>; the
			// lowercase path is what community repackagings use.
			"/opt/LM Studio",
			"/opt/lm-studio",
		} {
			if d.exec.DirExists(candidate) {
				appPath = candidate
				break
			}
		}
		if appPath == "" {
			return model.AITool{}, false
		}
		version = "unknown"
	}

	running := isProcessRunningFuzzy(ctx, d.exec, "LM Studio")

	return model.AITool{
		Name:       "lm-studio",
		Vendor:     "LM Studio",
		Type:       "framework",
		Version:    version,
		BinaryPath: appPath,
		IsRunning:  &running,
	}, true
}
