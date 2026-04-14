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

	// Quiet resolution: config is the base, CLI overrides.
	quiet := true
	if config.Quiet != nil {
		quiet = *config.Quiet
	}
	if cfg.Verbose {
		quiet = false
	}
	if cfg.OutputFormat == "json" {
		quiet = true
	}
	if cfg.Command == "send-telemetry" || cfg.Command == "install" {
		quiet = false
	}
	log := progress.NewLogger(quiet)

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
		if runtime.GOOS == "windows" {
			if err := schtasks.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		} else {
			if err := launchd.Install(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		}
		log.Progress("Sending initial telemetry...")
		fmt.Println()
		if err := telemetry.Run(exec, log, cfg); err != nil {
			log.Error("%v", err)
			os.Exit(1)
		}

	case "uninstall":
		_, _ = fmt.Fprintf(os.Stdout, "StepSecurity Dev Machine Guard v%s\n\n", buildinfo.Version)
		if runtime.GOOS == "windows" {
			if err := schtasks.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		} else {
			if err := launchd.Uninstall(exec, log); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		}

	default:
		// Community mode or auto-detect enterprise
		if cfg.OutputFormatSet || cfg.HTMLOutputFile != "" {
			// Output format flag was explicitly set — community mode
			if err := scan.Run(exec, log, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		} else if config.IsEnterpriseMode() {
			if err := telemetry.Run(exec, log, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		} else {
			if err := scan.Run(exec, log, cfg); err != nil {
				log.Error("%v", err)
				os.Exit(1)
			}
		}
	}
}
