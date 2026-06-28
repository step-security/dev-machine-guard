package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	aiagentscli "github.com/step-security/dev-machine-guard/internal/aiagents/cli"
	"github.com/step-security/dev-machine-guard/internal/aiagents/ingest"
	"github.com/step-security/dev-machine-guard/internal/aiagents/state"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/detector/configaudit"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/featuregate"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/launchd"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/output"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/progress/filelog"
	"github.com/step-security/dev-machine-guard/internal/scan"
	"github.com/step-security/dev-machine-guard/internal/schtasks"
	"github.com/step-security/dev-machine-guard/internal/systemd"
	"github.com/step-security/dev-machine-guard/internal/tcc"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
	"github.com/step-security/dev-machine-guard/internal/winproc"
)

// auditSkipper builds a TCC skipper if scanning into TCC-protected dirs is
// not opted in. Mirrors scan.Run / telemetry.Run so the focused *Only audits
// don't accidentally prompt the user on macOS.
func auditSkipper(exec executor.Executor, cfg *cli.Config) *tcc.Skipper {
	if !tcc.Enabled(cfg.IncludeTCCProtected) {
		return nil
	}
	return tcc.New(executor.ResolveHome(exec))
}

// hookReconcileTimeout caps the entire reconcile step (fetch + cache
// write + install/uninstall). Generous because install can chown a
// handful of files under root; the actual GET cost is bounded by
// state.DefaultFetchTimeout.
const hookReconcileTimeout = 30 * time.Second

func main() {
	// Hook hot path. Agents invoke `_hook` on every event and any non-zero
	// exit is treated as a hook failure / block — so we MUST exit 0 even on
	// malformed args. Skip every line below this branch (CLI parsing,
	// executor construction, logger setup) to keep the runtime budget
	// realistic; the 15s hook cap has to absorb identity probes and a 5s
	// upload, every millisecond here is dead weight. RunHook owns its own
	// minimal config.Load (just enough for the upload gate) so this branch
	// stays free of the rest of main's setup work.
	if len(os.Args) >= 2 && os.Args[1] == "_hook" {
		// Gated: silently no-op so any pre-existing hook entry that points
		// at this binary stays harmless until the feature ships. Override
		// flows in via STEPSECURITY_OVERRIDE_GATE since Parse hasn't run.
		if !featuregate.IsEnabled(featuregate.FeatureAIAgentHooks) {
			os.Exit(0)
		}
		os.Exit(aiagentscli.RunHook(os.Stdin, os.Stdout, os.Stderr, os.Args[2:]))
	}

	// Load persisted config (~/.stepsecurity/config.json) before parsing CLI
	config.Load()

	cfg, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}

	if cfg.OverrideGate {
		featuregate.EnableOverride()
	}

	// Apply saved config values if CLI didn't explicitly override them.
	// CLI flags always win over config file values (same as the shell script).
	if len(config.SearchDirs) > 0 && len(cfg.SearchDirs) == 1 && cfg.SearchDirs[0] == "$HOME" {
		cfg.SearchDirs = config.SearchDirs
	}
	if cfg.EnableNPMScan == nil && config.EnableNPMScan != nil {
		cfg.EnableNPMScan = config.EnableNPMScan
	}
	if cfg.EnableBrewScan == nil && config.EnableBrewScan != nil {
		cfg.EnableBrewScan = config.EnableBrewScan
	}
	if cfg.EnablePythonScan == nil && config.EnablePythonScan != nil {
		cfg.EnablePythonScan = config.EnablePythonScan
	}
	// --legacy-python-scan / --disk-python-scan override the config-file value
	// (which config.Load already applied to config.UseLegacyPythonScan).
	if cfg.UseLegacyPythonScan != nil {
		config.UseLegacyPythonScan = *cfg.UseLegacyPythonScan
	}
	if cfg.IncludeTCCProtected == nil && config.IncludeTCCProtected != nil {
		cfg.IncludeTCCProtected = config.IncludeTCCProtected
	}
	if cfg.ColorMode == "auto" && config.ColorMode != "" {
		cfg.ColorMode = config.ColorMode
	}
	if !cfg.OutputFormatSet && config.OutputFormat != "" {
		cfg.OutputFormat = config.OutputFormat
		// Note: do NOT set OutputFormatSet here — saved config is a default preference,
		// not an explicit CLI flag. Enterprise auto-detection should still work
		// when no CLI flags are passed.
		if config.OutputFormat == "html" && cfg.HTMLOutputFile == "" && config.HTMLOutputFile != "" {
			cfg.HTMLOutputFile = config.HTMLOutputFile
		}
	}

	exec := executor.NewReal()

	// Install dir resolution (see internal/paths.Home for the canonical
	// chain): --install-dir CLI flag > install_dir config field >
	// $STEPSECURITY_HOME env var > ~/.stepsecurity default. Config beats
	// env because config.json is the source of truth that the loader
	// scripts write to and operators hand-edit; the env var baked into
	// service unit files at install time can otherwise become stale.
	// An explicit `--install-dir=` (empty) routes through SetDisabled,
	// after which paths.Home() returns "" so EVERY on-disk consumer
	// (filelog, ai-agent hook errors, any future file) uniformly skips
	// — not just file logging. cli.Parse rejects the empty form when
	// paired with `install` / `uninstall`, where the platform installers
	// need a real on-disk path for unit files and the log directory.
	//
	// The capture is installed before the logger so every subsequent
	// stderr write — including the pipe-tee in
	// internal/telemetry/logcapture.go, which nests inside this one —
	// flows through to disk.
	if cfg.InstallDirSet {
		if cfg.InstallDir == "" {
			paths.SetDisabled()
		} else {
			paths.SetOverride(cfg.InstallDir)
		}
	}
	installDir := paths.Home() // "" when SetDisabled or home unresolved
	logFilePath := ""
	if installDir != "" {
		logFilePath = filepath.Join(installDir, filelog.Filename)
		// Pre-rotate BOTH files unconditionally. In interactive mode the
		// stderr rotation is redundant with filelog.Start's own rotation
		// pass (Start re-checks and no-ops on a missing path); in service
		// mode StartIfEligible early-returns and Start never runs, so this
		// explicit call is the only thing keeping agent.error.log bounded
		// when the OS-level scheduler redirect is writing it. agent.log
		// has the same property — the agent never writes it directly, so
		// the only opportunity to cap it is at startup.
		filelog.RotateIfOverCap(logFilePath, filelog.DefaultMaxBytes)
		filelog.RotateIfOverCap(filepath.Join(installDir, filelog.StdoutFilename), filelog.DefaultMaxBytes)
	}
	capture, captureErr := filelog.StartIfEligible(logFilePath, filelog.DefaultMaxBytes)
	defer func() { _ = capture.Stop() }()

	// Log level resolution: default info → config file → CLI flag → --verbose → JSON override.
	level := progress.LevelInfo
	if config.LogLevel != "" {
		if l, ok := progress.ParseLevel(config.LogLevel); ok {
			level = l
		}
	}
	if cfg.LogLevel != "" {
		if l, ok := progress.ParseLevel(cfg.LogLevel); ok {
			level = l
		}
	}
	if cfg.Verbose {
		level = progress.LevelDebug
	}
	if cfg.OutputFormat == "json" {
		// Keep stdout clean for pipes: only errors on stderr.
		level = progress.LevelError
	}
	log := progress.NewLogger(level)
	if captureErr != nil {
		// Non-fatal: a read-only $HOME shouldn't block the run.
		log.Warn("file logging disabled: %v", captureErr)
	}

	// Migration heads-up: if the operator has moved the install dir but
	// the legacy ~/.stepsecurity still has agent state, surface that so
	// they can decide whether to copy over old diagnostic files. Don't
	// auto-move — too risky for v1 (silent overwrites, races with other
	// processes, perms changes). Just point at the leftovers.
	legacy := paths.LegacyHome()
	if legacy != "" && installDir != "" && installDir != legacy {
		if leftovers := findLegacyLeftovers(legacy); len(leftovers) > 0 {
			log.Warn("install dir is %s but the legacy default %s still has files: %s — copy them over manually if you want their history.",
				installDir, legacy, strings.Join(leftovers, ", "))
		}
	}
	log.Debug("resolved log level: %s (config=%q cli=%q verbose=%v output=%s)",
		level, config.LogLevel, cfg.LogLevel, cfg.Verbose, cfg.OutputFormat)
	log.Debug("config loaded: enterprise=%v api_endpoint=%q scan_freq=%q search_dirs=%v log_level=%q",
		config.IsEnterpriseMode(), config.APIEndpoint, config.ScanFrequencyHours, config.SearchDirs, config.LogLevel)
	log.Debug("cli parsed: command=%q output_format=%q output_format_set=%v color=%s include_bundled=%v",
		cfg.Command, cfg.OutputFormat, cfg.OutputFormatSet, cfg.ColorMode, cfg.IncludeBundledPlugins)

	switch cfg.Command {
	case "configure":
		// Non-interactive path: any explicit config flag, an explicit
		// --non-interactive, OR the DMG_API_KEY env var route configure
		// through the no-prompt code path. This is how MSI/SCCM/Intune
		// custom actions drive configuration — they can't talk to stdin.
		opts := config.NonInteractiveOptions{
			FromFile:      cfg.ConfigFromFile,
			CustomerID:    cfg.ConfigCustomerID,
			APIEndpoint:   cfg.ConfigAPIEndpoint,
			APIKey:        cfg.ConfigAPIKey,
			ScanFrequency: cfg.ConfigScanFrequency,
		}
		if opts.APIKey == "" {
			// Env-var fallback keeps the secret off the msiexec command
			// line (which lands in AppEnforce.log on every endpoint).
			opts.APIKey = os.Getenv("DMG_API_KEY")
		}
		// Only forward --search-dirs to configure when the user actually
		// passed it on this invocation. (cli.Parse defaults SearchDirs to
		// ["$HOME"] for the scan path, which we must not persist here.)
		if len(cfg.SearchDirs) > 0 && !(len(cfg.SearchDirs) == 1 && cfg.SearchDirs[0] == "$HOME") {
			opts.SearchDirs = cfg.SearchDirs
		}
		if cfg.NonInteractive || opts.HasAny() {
			if err := config.RunConfigureNonInteractive(opts); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			if err := config.RunConfigure(); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		}

	case "configure show":
		config.ShowConfigure()

	case "send-telemetry":
		// Stamp the local heartbeat first — before the enterprise gate and
		// the singleton lock inside telemetry.Run — so even runs that bail at
		// the gate or die during startup leave an on-disk "I started" record.
		writeHeartbeat(exec, "send-telemetry", log)
		if !config.IsEnterpriseMode() {
			log.Error("Enterprise configuration not found. Run '%s configure' or download the script from your StepSecurity dashboard.", os.Args[0])
			os.Exit(1)
		}
		armExecutionWatchdog(telemetry.ExecutionDeadline(config.MaxExecutionDuration), log)
		if err := telemetry.Run(exec, log, cfg); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}
		runHookStateReconcile(exec, log)

	case "install":
		_, _ = fmt.Fprintf(os.Stdout, "StepSecurity Dev Machine Guard v%s\n\n", buildinfo.Version)
		if !config.IsEnterpriseMode() {
			log.Error("Enterprise configuration not found. Run '%s configure' or download the script from your StepSecurity dashboard.", os.Args[0])
			os.Exit(1)
		}
		switch runtime.GOOS {
		case model.PlatformWindows:
			if err := schtasks.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case model.PlatformDarwin:
			if err := launchd.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case model.PlatformLinux:
			if err := systemd.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		default:
			log.Error("Scheduled installation is not supported on %s", runtime.GOOS)
			os.Exit(1)
		}

		// Persist the loader-exported max-execution duration into config.json so
		// scheduler-fired runs (launchd/systemd/schtasks) — which invoke the
		// binary directly and never inherit the loader's exported env var — arm
		// the watchdog with the same value. Best-effort: a write failure just
		// means scheduled runs fall back to the binary's built-in default.
		if err := config.PersistMaxExecutionDuration(os.Getenv(telemetry.EnvMaxExecutionDuration)); err != nil {
			log.Warn("failed to persist max execution duration to config (%v) — scheduled runs will use the built-in default", err)
		}

		// MSI deferred custom actions run as NT AUTHORITY\SYSTEM. A scan
		// from that context sees SYSTEM's profile (no IDEs, no AI agents,
		// no user dotfiles) and ships a near-empty payload as the first
		// data point — the symptom customers reported as "first run is
		// empty, subsequent runs are correct." Instead of scanning inline,
		// ask the scheduler to fire the just-registered task, which is
		// bound to /ru INTERACTIVE and runs under the logged-in user.
		// If no one is logged in (unattended SCCM deploys), the trigger
		// silently no-ops and the task fires on its next hourly tick;
		// either way, no SYSTEM-context telemetry ever ships.
		if runtime.GOOS == model.PlatformWindows && winproc.IsLocalSystem() {
			if err := schtasks.RunNow(exec, log); err != nil {
				log.Warn("could not trigger initial scan (%v) — the scheduled task will fire on its next interval", err)
			}
			runHookStateReconcile(exec, log)
			return
		}

		// On macOS, launchd.Install already loaded the plist, and RunAtLoad=true
		// runs the initial scan immediately under the user's GUI session. Don't
		// also scan inline here — that would double-scan at install (two TCC
		// rounds + two uploads), with the second run blocked on the singleton
		// lock. Mirrors the Windows-SYSTEM path above; the launchd-triggered
		// scan's output lands in agent.log.
		if runtime.GOOS == model.PlatformDarwin {
			runHookStateReconcile(exec, log)
			return
		}

		log.Progress("Sending initial telemetry...")
		fmt.Println()
		armExecutionWatchdog(telemetry.ExecutionDeadline(config.MaxExecutionDuration), log)
		telemetryErr := telemetry.Run(exec, log, cfg)

		// On Linux, systemd.Install enabled the timer but did not start it.
		// Start it now that the inline scan above has released the singleton
		// lock, so the timer's first (Persistent=true catch-up) firing does
		// not race with that scan (issue #62). Run regardless of the
		// telemetry result — the install itself succeeded and the schedule
		// should activate; a failed initial telemetry run does not undo it.
		if runtime.GOOS == model.PlatformLinux {
			if err := systemd.StartTimer(exec, log); err != nil {
				log.Warn("timer start failed (%v) — scheduled scans will resume after the next user-systemd reload", err)
			}
		}

		if telemetryErr != nil {
			if cfg.IgnoreTelemetryError {
				// Opt-in tolerance for MSI/SCCM/Intune deployments: the
				// scheduled task is already registered and will retry
				// telemetry on its next firing, so a transient first-run
				// network hiccup shouldn't roll back the whole install.
				// Default (dev-workflow) behavior remains exit non-zero
				// to surface real misconfigurations during interactive use.
				log.Warn("initial telemetry failed (%v) — the scheduled task will retry on its next firing", telemetryErr)
			} else {
				log.Error("%v", telemetryErr)
				os.Exit(1)
			}
		}
		runHookStateReconcile(exec, log)

	case "uninstall":
		_, _ = fmt.Fprintf(os.Stdout, "StepSecurity Dev Machine Guard v%s\n\n", buildinfo.Version)
		switch runtime.GOOS {
		case model.PlatformWindows:
			if err := schtasks.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case model.PlatformDarwin:
			if err := launchd.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case model.PlatformLinux:
			if err := systemd.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		default:
			log.Error("Scheduled installation is not supported on %s", runtime.GOOS)
			os.Exit(1)
		}

	case "hooks install":
		if !featuregate.IsEnabled(featuregate.FeatureAIAgentHooks) {
			fmt.Fprintln(os.Stderr, featuregate.UnavailableMessage("hooks install"))
			os.Exit(1)
		}
		os.Exit(aiagentscli.RunInstall(context.Background(), exec, cfg.HooksAgent, os.Stdout, os.Stderr))

	case "hooks uninstall":
		if !featuregate.IsEnabled(featuregate.FeatureAIAgentHooks) {
			fmt.Fprintln(os.Stderr, featuregate.UnavailableMessage("hooks uninstall"))
			os.Exit(1)
		}
		os.Exit(aiagentscli.RunUninstall(context.Background(), exec, cfg.HooksAgent, os.Stdout, os.Stderr))

	default:
		// --npmrc and --pipconfig: focused, verbose pretty audits that
		// bypass everything else for a fast (~1s) deep dive.
		if cfg.NPMRCOnly {
			if !featuregate.IsEnabled(featuregate.FeatureNPMRCAudit) {
				fmt.Fprintln(os.Stderr, featuregate.UnavailableMessage("--npmrc"))
				os.Exit(1)
			}
			if err := runNPMRCOnly(exec, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
			return
		}
		if cfg.PipConfigOnly {
			if !featuregate.IsEnabled(featuregate.FeaturePipConfigAudit) {
				fmt.Fprintln(os.Stderr, featuregate.UnavailableMessage("--pipconfig"))
				os.Exit(1)
			}
			if err := runPipConfigOnly(exec, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
			return
		}
		if cfg.PnpmRCOnly {
			if !featuregate.IsEnabled(featuregate.FeaturePnpmConfigAudit) {
				fmt.Fprintln(os.Stderr, featuregate.UnavailableMessage("--pnpmrc"))
				os.Exit(1)
			}
			if err := runPnpmRCOnly(exec, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
			return
		}
		if cfg.BunfigOnly {
			if !featuregate.IsEnabled(featuregate.FeatureBunConfigAudit) {
				fmt.Fprintln(os.Stderr, featuregate.UnavailableMessage("--bunfig"))
				os.Exit(1)
			}
			if err := runBunfigOnly(exec, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
			return
		}
		if cfg.YarnRCOnly {
			if !featuregate.IsEnabled(featuregate.FeatureYarnConfigAudit) {
				fmt.Fprintln(os.Stderr, featuregate.UnavailableMessage("--yarnrc"))
				os.Exit(1)
			}
			if err := runYarnRCOnly(exec, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
			return
		}
		// Community mode or auto-detect enterprise
		switch {
		case cfg.OutputFormatSet || cfg.HTMLOutputFile != "":
			// Output format flag was explicitly set — community mode
			log.Debug("dispatch: community scan (output format flag set)")
			if err := scan.Run(exec, log, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case config.IsEnterpriseMode():
			log.Debug("dispatch: enterprise telemetry (auto-detected)")
			armExecutionWatchdog(telemetry.ExecutionDeadline(config.MaxExecutionDuration), log)
			if err := telemetry.Run(exec, log, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		default:
			log.Debug("dispatch: community scan (default)")
			if err := scan.Run(exec, log, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		}
	}
}

// runNPMRCOnly executes only the npmrc detector and renders the verbose
// pretty view (or JSON when --json is also passed). Skips IDE / AI / Brew /
// Python / Node / pip detection so the run is fast and the output is
// exclusively about npm configuration.
func runNPMRCOnly(exec executor.Executor, cfg *cli.Config) error {
	ctx := context.Background()
	dev := device.Gather(ctx, exec)
	loggedInUser, _ := exec.LoggedInUser()

	searchDirs := resolveScanSearchDirs(exec, cfg.SearchDirs)
	audit := configaudit.NewNPMRCDetector(exec).Detect(ctx, searchDirs, loggedInUser)

	if cfg.OutputFormat == "json" {
		return scanJSONEncoder(os.Stdout).Encode(audit)
	}
	output.PrettyNPMRC(os.Stdout, &audit, dev, cfg.ColorMode)
	return nil
}

// runPipConfigOnly executes only the pip-config detector and renders the
// verbose pretty view (or JSON when --json is also passed).
func runPipConfigOnly(exec executor.Executor, cfg *cli.Config) error {
	ctx := context.Background()
	dev := device.Gather(ctx, exec)
	loggedInUser, _ := exec.LoggedInUser()

	audit := configaudit.NewPipConfigDetector(exec).Detect(ctx, loggedInUser)

	if cfg.OutputFormat == "json" {
		return scanJSONEncoder(os.Stdout).Encode(audit)
	}
	output.PrettyPipConfig(os.Stdout, &audit, dev, cfg.ColorMode)
	return nil
}

// runPnpmRCOnly executes only the pnpm detector and renders the verbose
// pretty view (or JSON when --json is also passed).
func runPnpmRCOnly(exec executor.Executor, cfg *cli.Config) error {
	ctx := context.Background()
	dev := device.Gather(ctx, exec)
	loggedInUser, _ := exec.LoggedInUser()

	searchDirs := resolveScanSearchDirs(exec, cfg.SearchDirs)
	audit := configaudit.NewPnpmDetector(exec).WithSkipper(auditSkipper(exec, cfg)).Detect(ctx, searchDirs, loggedInUser)

	if cfg.OutputFormat == "json" {
		return scanJSONEncoder(os.Stdout).Encode(audit)
	}
	output.PrettyPnpm(os.Stdout, &audit, dev, cfg.ColorMode)
	return nil
}

// runBunfigOnly executes only the bun detector and renders the verbose
// pretty view (or JSON when --json is also passed).
func runBunfigOnly(exec executor.Executor, cfg *cli.Config) error {
	ctx := context.Background()
	dev := device.Gather(ctx, exec)
	loggedInUser, _ := exec.LoggedInUser()

	searchDirs := resolveScanSearchDirs(exec, cfg.SearchDirs)
	audit := configaudit.NewBunDetector(exec).WithSkipper(auditSkipper(exec, cfg)).Detect(ctx, searchDirs, loggedInUser)

	if cfg.OutputFormat == "json" {
		return scanJSONEncoder(os.Stdout).Encode(audit)
	}
	output.PrettyBun(os.Stdout, &audit, dev, cfg.ColorMode)
	return nil
}

// runYarnRCOnly executes only the yarn detector (covering both .yarnrc and
// .yarnrc.yml) and renders the verbose pretty view (or JSON when --json is
// also passed).
func runYarnRCOnly(exec executor.Executor, cfg *cli.Config) error {
	ctx := context.Background()
	dev := device.Gather(ctx, exec)
	loggedInUser, _ := exec.LoggedInUser()

	searchDirs := resolveScanSearchDirs(exec, cfg.SearchDirs)
	audit := configaudit.NewYarnDetector(exec).WithSkipper(auditSkipper(exec, cfg)).Detect(ctx, searchDirs, loggedInUser)

	if cfg.OutputFormat == "json" {
		return scanJSONEncoder(os.Stdout).Encode(audit)
	}
	output.PrettyYarn(os.Stdout, &audit, dev, cfg.ColorMode)
	return nil
}

// resolveScanSearchDirs expands `$HOME` to the logged-in user's home dir
// and leaves other entries unchanged. Mirrors the helper inside scan.Run
// so --npmrc walks the same project tree the full scan would.
func resolveScanSearchDirs(exec executor.Executor, dirs []string) []string {
	resolved := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "$HOME" {
			if u, err := exec.LoggedInUser(); err == nil {
				d = u.HomeDir
			}
		}
		resolved = append(resolved, d)
	}
	return resolved
}

// scanJSONEncoder returns a 2-space-indented JSON encoder that doesn't
// HTML-escape — same conventions as the standard scan output.
func scanJSONEncoder(w io.Writer) *json.Encoder {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc
}

// findLegacyLeftovers checks the legacy ~/.stepsecurity dir for agent
// files the operator may have moved (intentionally) to a new install
// dir. Returns basenames of present diagnostic files (config.json is
// excluded — it must stay at the legacy path as the bootstrap, so its
// presence there is expected and not a leftover to migrate).
func findLegacyLeftovers(legacy string) []string {
	candidates := []string{
		"agent.error.log",
		"agent.error.log.prev",
		"agent.log",
		"agent.log.prev",
		"ai-agent-hook-errors.jsonl",
	}
	var found []string
	for _, name := range candidates {
		if _, err := os.Stat(filepath.Join(legacy, name)); err == nil {
			found = append(found, name)
		}
	}
	return found
}

// runHookStateReconcile polls agent-api for the desired AI-agent hook
// state and reconciles local hook installation to match. Silent no-op
// in community mode (enterprise config missing) — the existing scan
// path stays unaffected. Failures are logged but never crash main.
// writeHeartbeat stamps last-run.json with this run's start metadata. Wholly
// best-effort: a write failure (read-only home, disabled install dir) is
// logged at debug and never affects the run. The invocation method reuses the
// scheduler-footprint detection telemetry already does, so the heartbeat
// distinguishes a scheduled fire from a manual run.
func writeHeartbeat(exec executor.Executor, command string, log *progress.Logger) {
	if err := heartbeat.Write(paths.HeartbeatFile(), command, telemetry.DetectInvocationMethod(exec, log)); err != nil {
		log.Debug("heartbeat: failed to write %s: %v", paths.HeartbeatFile(), err)
	}
}

func runHookStateReconcile(exec executor.Executor, log *progress.Logger) {
	if !featuregate.IsEnabled(featuregate.FeatureAIAgentHooks) {
		log.Debug("hook-state reconcile: skipped (feature gated)")
		return
	}
	cfg, ok := ingest.Snapshot()
	if !ok {
		log.Debug("hook-state reconcile: skipped (no enterprise config)")
		return
	}
	fetcher, ok := state.NewHTTPFetcher(cfg, nil)
	if !ok {
		log.Debug("hook-state reconcile: skipped (fetcher init refused config)")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), hookReconcileTimeout)
	defer cancel()

	dev := device.Gather(ctx, exec)
	if dev.SerialNumber == "" || dev.SerialNumber == "unknown" {
		log.Warn("hook-state reconcile: device serial unresolved; skipping")
		return
	}

	r := &state.Reconciler{
		Exec:        exec,
		Fetcher:     fetcher,
		CustomerID:  cfg.CustomerID,
		DeviceID:    dev.SerialNumber,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		InstallFn:   aiagentscli.RunInstall,
		UninstallFn: aiagentscli.RunUninstall,
	}
	if err := r.Reconcile(ctx); err != nil {
		log.Warn("hook-state reconcile: %v", err)
		aiagentscli.AppendError("reconcile", "reconcile_failed", err.Error(), "")
	}
}
