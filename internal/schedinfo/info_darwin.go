//go:build darwin

package schedinfo

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/launchd"
)

func gather(ctx context.Context, exec executor.Executor) Info {
	info := Info{
		Platform:        "darwin",
		Manager:         "launchd",
		Label:           launchd.Label,
		ConfiguredHours: configuredHours(),
		Management:      ManagementUnknown,
		LogMtime:        logMtime(),
	}

	// Resolve the plist for this run's privilege level (root LaunchDaemon vs
	// per-user LaunchAgent), mirroring the install/uninstall paths.
	plistPath := launchd.DaemonPlistPath
	if !exec.IsRoot() {
		plistPath = launchd.UserPlistPath()
	}
	info.UnitPath = plistPath
	info.Scheduled = exec.FileExists(plistPath)

	// Parse the plist directly — it's our own well-formed XML, so reading
	// StartInterval/RunAtLoad/ProgramArguments from disk is more robust than
	// scraping plutil and needs no subprocess.
	if data, err := os.ReadFile(plistPath); err == nil {
		if pl, perr := parsePlist(data); perr == nil {
			if pl.StartInterval > 0 {
				info.IntervalSeconds = pl.StartInterval
			}
			ral := pl.RunAtLoad
			info.RunAtLoad = &ral
			info.Management = managementFromCmd(strings.Join(pl.ProgramArguments, " "))
		} else {
			info.Warnings = append(info.Warnings, fmt.Sprintf("parse plist %s: %v", plistPath, perr))
		}
	} else if info.Scheduled {
		info.Warnings = append(info.Warnings, fmt.Sprintf("read plist %s: %v", plistPath, err))
	}

	// Live runtime state via `launchctl print <domain>/<label>` — parsed for
	// state / pid / last-exit-code. We deliberately do NOT dump its full output:
	// it's ~100 lines of internal launchd detail (endpoints, sandbox, inherited
	// env) that's noise for troubleshooting. The concise plist config below is
	// the illustrative dump instead.
	domain, target := launchd.DomainTarget(exec)
	stdout, stderr, code, err := exec.RunWithTimeout(ctx, queryTimeout, "launchctl", "print", target)
	switch {
	case err != nil:
		info.Warnings = append(info.Warnings, fmt.Sprintf("launchctl print %s: %v", target, err))
	case code != 0:
		// Expected on no-GUI / SSH sessions ("Could not find service ...",
		// "Bootstrap failed: 5") — see docs/launchd-troubleshooting.md.
		info.Warnings = append(info.Warnings, fmt.Sprintf("launchctl print %s exited %d: %s", target, code, firstLine(stderr)))
	default:
		info.Loaded = true
		applyLaunchctlPrint(&info, stdout)
	}

	// Fallback: `launchctl list <label>` for last exit + pid when print failed.
	if !info.Loaded {
		if out, _, c, e := exec.RunWithTimeout(ctx, queryTimeout, "launchctl", "list", launchd.Label); e == nil && c == 0 {
			info.Loaded = strings.Contains(out, "LastExitStatus") || strings.Contains(out, launchd.Label)
			applyLaunchctlList(&info, out)
		}
	}
	_ = domain // domain currently informational; target carries it

	// Illustrative config dump: `plutil -p` of the plist — the focused, readable
	// schedule config (Label, ProgramArguments, StartInterval, RunAtLoad, env),
	// the macOS analog of `schtasks /query /v`, far less noisy than launchctl print.
	if out, _, c, e := exec.RunWithTimeout(ctx, queryTimeout, "plutil", "-p", plistPath); e == nil && c == 0 {
		info.Raw = strings.TrimSpace(out)
	}

	// launchd exposes no "next fire" for a StartInterval job, so estimate it from
	// the last run (agent.log mtime) + the interval. Labeled an estimate so it's
	// not mistaken for a value launchd reported.
	if !info.LogMtime.IsZero() && info.IntervalSeconds > 0 {
		next := info.LogMtime.Add(time.Duration(info.IntervalSeconds) * time.Second)
		info.NextRunTime = next.Format(time.RFC3339) + " (estimated: last run + interval)"
	}

	// Drift note: plist interval vs configured hours is a real misconfig signal.
	if info.IntervalSeconds > 0 && info.ConfiguredHours > 0 && info.IntervalSeconds != info.ConfiguredHours*3600 {
		info.Warnings = append(info.Warnings, fmt.Sprintf(
			"plist StartInterval=%ds disagrees with config scan_frequency_hours=%d (%ds)",
			info.IntervalSeconds, info.ConfiguredHours, info.ConfiguredHours*3600))
	}

	return info
}
