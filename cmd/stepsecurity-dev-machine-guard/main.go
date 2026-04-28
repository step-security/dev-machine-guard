package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/launchd"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/scan"
	"github.com/step-security/dev-machine-guard/internal/schtasks"
	"github.com/step-security/dev-machine-guard/internal/systemd"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
)

func main() {
	// Load persisted config (~/.stepsecurity/config.json) before parsing CLI
	config.Load()

	cfg, err := cli.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
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
	log.Debug("resolved log level: %s (config=%q cli=%q verbose=%v output=%s)",
		level, config.LogLevel, cfg.LogLevel, cfg.Verbose, cfg.OutputFormat)
	log.Debug("config loaded: enterprise=%v api_endpoint=%q scan_freq=%q search_dirs=%v log_level=%q",
		config.IsEnterpriseMode(), config.APIEndpoint, config.ScanFrequencyHours, config.SearchDirs, config.LogLevel)
	log.Debug("cli parsed: command=%q output_format=%q output_format_set=%v color=%s include_bundled=%v",
		cfg.Command, cfg.OutputFormat, cfg.OutputFormatSet, cfg.ColorMode, cfg.IncludeBundledPlugins)

	switch cfg.Command {
	case "configure":
		if err := config.RunConfigure(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case "configure show":
		config.ShowConfigure()

	case "send-telemetry":
		if !config.IsEnterpriseMode() {
			log.Error("Enterprise configuration not found. Run '%s configure' or download the script from your StepSecurity dashboard.", os.Args[0])
			os.Exit(1)
		}
		if err := telemetry.Run(exec, log, cfg); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}

	case "install":
		_, _ = fmt.Fprintf(os.Stdout, "StepSecurity Dev Machine Guard v%s\n\n", buildinfo.Version)
		if !config.IsEnterpriseMode() {
			log.Error("Enterprise configuration not found. Run '%s configure' or download the script from your StepSecurity dashboard.", os.Args[0])
			os.Exit(1)
		}
		switch runtime.GOOS {
		case "windows":
			if err := schtasks.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case "darwin":
			if err := launchd.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case "linux":
			if err := systemd.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		default:
			log.Error("Scheduled installation is not supported on %s", runtime.GOOS)
			os.Exit(1)
		}
		log.Progress("Sending initial telemetry...")
		fmt.Println()
		if err := telemetry.Run(exec, log, cfg); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}

	case "uninstall":
		_, _ = fmt.Fprintf(os.Stdout, "StepSecurity Dev Machine Guard v%s\n\n", buildinfo.Version)
		switch runtime.GOOS {
		case "windows":
			if err := schtasks.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case "darwin":
			if err := launchd.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		case "linux":
			if err := systemd.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		default:
			log.Error("Scheduled installation is not supported on %s", runtime.GOOS)
			os.Exit(1)
		}

	default:
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
