package telemetry

import (
	"os"
	"runtime"

	"github.com/step-security/dev-machine-guard/internal/launchd"
	"github.com/step-security/dev-machine-guard/internal/schtasks"
	"github.com/step-security/dev-machine-guard/internal/systemd"
)

// Wire-format values for the invocation_method field. Kept stable —
// console and backend match on these literal strings.
const (
	InvocationInstall = "install"
	InvocationOneTime = "one_time"
)

// DetectInvocationMethod returns "install" when the dev-machine-guard
// scheduler footprint is present on this machine, else "one_time".
//
// The check is best-effort and never returns an error: a stat failure or a
// flaky schtasks call degrades to "one_time" so an unknown environment is
// never misreported as an installed agent. Detection is filesystem-based on
// darwin/linux and a single schtasks query on windows, so an agent rolled
// out before this code shipped starts reporting "install" on its next
// scheduled fire without any installer changes.
func DetectInvocationMethod() string {
	if isSchedulerInstalled() {
		return InvocationInstall
	}
	return InvocationOneTime
}

func isSchedulerInstalled() bool {
	switch runtime.GOOS {
	case "darwin":
		return fileExists(launchd.DaemonPlistPath) || fileExists(launchd.UserPlistPath())
	case "linux":
		return fileExists(systemd.TimerUnitPath())
	case "windows":
		return schtasks.IsTaskRegistered()
	default:
		return false
	}
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
