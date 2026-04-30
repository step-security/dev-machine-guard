//go:build !windows

package device

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// getSerialNumberWindows uses exec.Run when not compiled for Windows.
// This path is used by mock-based tests that simulate Windows via SetGOOS("windows").
func getSerialNumberWindows(ctx context.Context, exec executor.Executor) string {
	stdout, _, _, err := exec.Run(ctx, "wmic", "bios", "get", "serialnumber")
	if err == nil {
		lines := strings.Split(strings.TrimSpace(stdout), "\n")
		if len(lines) >= 2 {
			serial := strings.TrimSpace(lines[1])
			if serial != "" && serial != "SerialNumber" {
				return serial
			}
		}
	}
	stdout, _, _, err = exec.Run(ctx, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance -ClassName Win32_BIOS).SerialNumber")
	if err == nil {
		s := strings.TrimSpace(stdout)
		if s != "" {
			return s
		}
	}
	return "unknown"
}

// getOSVersionWindows uses exec.Run when not compiled for Windows.
func getOSVersionWindows(ctx context.Context, exec executor.Executor) string {
	stdout, _, _, err := exec.Run(ctx, "powershell", "-NoProfile", "-Command",
		"[System.Environment]::OSVersion.Version.ToString()")
	if err == nil {
		v := strings.TrimSpace(stdout)
		if v != "" {
			return v
		}
	}
	return "unknown"
}
