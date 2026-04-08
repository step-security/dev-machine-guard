package device

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Gather collects device information (hostname, serial, OS version, user identity).
func Gather(ctx context.Context, exec executor.Executor) model.Device {
	hostname, _ := exec.Hostname()
	userIdentity := getDeveloperIdentity(exec)
	platform := exec.GOOS()

	var serial, osVersion string
	switch platform {
	case "windows":
		serial = getSerialNumberWindows(ctx, exec)
		osVersion = getOSVersionWindows(ctx, exec)
	default:
		serial = getSerialNumber(ctx, exec)
		osVersion = getOSVersion(ctx, exec)
	}

	return model.Device{
		Hostname:     hostname,
		SerialNumber: serial,
		OSVersion:    osVersion,
		Platform:     platform,
		UserIdentity: userIdentity,
	}
}

func getSerialNumberWindows(ctx context.Context, exec executor.Executor) string {
	// Try wmic
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
	// Fallback: PowerShell
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

func getSerialNumber(ctx context.Context, exec executor.Executor) string {
	// Try ioreg first
	stdout, _, _, err := exec.Run(ctx, "ioreg", "-l")
	if err == nil {
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, "IOPlatformSerialNumber") {
				parts := strings.Split(line, "=")
				if len(parts) >= 2 {
					serial := strings.TrimSpace(parts[1])
					serial = strings.Trim(serial, "\" ")
					if serial != "" {
						return serial
					}
				}
			}
		}
	}

	// Fallback: system_profiler
	stdout, _, _, err = exec.Run(ctx, "system_profiler", "SPHardwareDataType")
	if err == nil {
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, "Serial") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					serial := strings.TrimSpace(parts[1])
					if serial != "" {
						return serial
					}
				}
			}
		}
	}

	return "unknown"
}

func getOSVersion(ctx context.Context, exec executor.Executor) string {
	stdout, _, _, err := exec.Run(ctx, "sw_vers", "-productVersion")
	if err == nil {
		v := strings.TrimSpace(stdout)
		if v != "" {
			return v
		}
	}
	return "unknown"
}

func getDeveloperIdentity(exec executor.Executor) string {
	// Check environment variables in order of preference
	for _, key := range []string{"USER_EMAIL", "DEVELOPER_EMAIL", "STEPSEC_DEVELOPER_EMAIL"} {
		if v := exec.Getenv(key); v != "" {
			return v
		}
	}
	// Fallback to current username
	u, err := exec.CurrentUser()
	if err == nil {
		return u.Username
	}
	return "unknown"
}
