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
	case model.PlatformWindows:
		serial = getSerialNumberWindows(ctx, exec)
		osVersion = getOSVersionWindows(ctx, exec)
	case model.PlatformDarwin:
		serial = getSerialNumber(ctx, exec)
		osVersion = getOSVersion(ctx, exec)
	default: // linux and other unix
		serial = getSerialNumberLinux(ctx, exec)
		osVersion = getOSVersionLinux(ctx, exec)
	}

	return model.Device{
		Hostname:     hostname,
		SerialNumber: serial,
		OSVersion:    osVersion,
		Platform:     platform,
		UserIdentity: userIdentity,
	}
}

// getSerialNumberWindows and getOSVersionWindows are implemented in
// device_windows.go (native API) and device_other.go (stub).

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

func getSerialNumberLinux(ctx context.Context, exec executor.Executor) string {
	// Try /sys/class/dmi/id/product_serial (readable without root on most distros)
	if data, err := exec.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" && s != "None" && s != "To Be Filled By O.E.M." {
			return s
		}
	}

	// Fallback: dmidecode (requires root)
	stdout, _, _, err := exec.Run(ctx, "dmidecode", "-s", "system-serial-number")
	if err == nil {
		s := strings.TrimSpace(stdout)
		if s != "" && s != "None" && s != "To Be Filled By O.E.M." {
			return s
		}
	}

	// Fallback: machine-id (always available, unique per install)
	if data, err := exec.ReadFile("/etc/machine-id"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "" {
			return s
		}
	}

	return "unknown"
}

func getOSVersionLinux(ctx context.Context, exec executor.Executor) string {
	var distro, kernel string

	// Distro name from /etc/os-release
	if data, err := exec.ReadFile("/etc/os-release"); err == nil {
		var prettyName, versionID string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				prettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				versionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
			}
		}
		if prettyName != "" {
			distro = prettyName
		} else if versionID != "" {
			distro = versionID
		}
	}

	// Fallback distro: lsb_release
	if distro == "" {
		stdout, _, _, err := exec.Run(ctx, "lsb_release", "-d", "-s")
		if err == nil {
			distro = strings.TrimSpace(stdout)
		}
	}

	// Kernel version: read /proc/sys/kernel/osrelease (avoids subprocess)
	if data, err := exec.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		kernel = strings.TrimSpace(string(data))
	}

	// Compose: "Fedora Linux 42 (Cloud Edition) - 6.19.12-100.fc42.x86_64"
	switch {
	case distro != "" && kernel != "":
		return distro + " - " + kernel
	case distro != "":
		return distro
	case kernel != "":
		return kernel
	default:
		return "unknown"
	}
}

func getDeveloperIdentity(exec executor.Executor) string {
	// Check environment variables in order of preference
	for _, key := range []string{"USER_EMAIL", "DEVELOPER_EMAIL", "STEPSEC_DEVELOPER_EMAIL"} {
		if v := exec.Getenv(key); v != "" {
			return v
		}
	}
	// Fallback to logged-in username (detects console user when running as root)
	u, err := exec.LoggedInUser()
	if err == nil {
		return u.Username
	}
	return "unknown"
}
