package detector

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// isProcessRunning checks if a process with the given name is running.
// On Linux, reads /proc/<pid>/comm directly (no subprocess).
// On Windows, uses native CreateToolhelp32Snapshot API (no subprocess).
// On macOS, uses pgrep -x.
func isProcessRunning(ctx context.Context, exec executor.Executor, name string) bool {
	if exec.GOOS() == model.PlatformWindows {
		return processMatchExact(ctx, exec, name)
	}
	if exec.GOOS() == model.PlatformLinux {
		return procMatchExact(exec, name)
	}
	// macOS: pgrep
	_, _, exitCode, _ := exec.Run(ctx, "pgrep", "-x", name)
	return exitCode == 0
}

// isProcessRunningFuzzy checks if any process matches a substring pattern.
// On Linux, reads /proc/<pid>/cmdline directly (no subprocess).
// On Windows, uses native CreateToolhelp32Snapshot API (no subprocess).
// On macOS, uses pgrep -f.
func isProcessRunningFuzzy(ctx context.Context, exec executor.Executor, pattern string) bool {
	if exec.GOOS() == model.PlatformWindows {
		return processMatchFuzzy(ctx, exec, pattern)
	}
	if exec.GOOS() == model.PlatformLinux {
		return procMatchFuzzy(exec, pattern)
	}
	// macOS: pgrep
	_, _, exitCode, _ := exec.Run(ctx, "pgrep", "-f", pattern)
	return exitCode == 0
}

// procMatchExact scans /proc to find a process whose comm matches name exactly.
func procMatchExact(exec executor.Executor, name string) bool {
	entries, err := exec.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		data, err := exec.ReadFile("/proc/" + entry.Name() + "/comm")
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == name {
			return true
		}
	}
	return false
}

// procMatchFuzzy scans /proc to find a process whose cmdline contains the pattern.
func procMatchFuzzy(exec executor.Executor, pattern string) bool {
	entries, err := exec.ReadDir("/proc")
	if err != nil {
		return false
	}
	lowerPattern := strings.ToLower(pattern)
	for _, entry := range entries {
		if !entry.IsDir() || !isNumeric(entry.Name()) {
			continue
		}
		data, err := exec.ReadFile("/proc/" + entry.Name() + "/cmdline")
		if err != nil {
			continue
		}
		// cmdline uses null bytes as separators
		cmdline := strings.ToLower(strings.ReplaceAll(string(data), "\x00", " "))
		if strings.Contains(cmdline, lowerPattern) {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
