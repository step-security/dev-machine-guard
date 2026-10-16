package device

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/wslguest"
	"howett.net/plist"
)

// ID returns the device identity every backend call uses: the identity
// Gather resolved (a configured template or literal, else the machine
// identity), or "" when none is usable (never a placeholder like "unknown").
// A Device not produced by Gather falls back to the configured literal (or
// template, expanded from the Device's own fields) and then its serial. Keep
// SerialNumber separate so telemetry retains the hardware identity.
func ID(dev model.Device) string {
	if dev.DeviceID != "" {
		return dev.DeviceID
	}
	if dev.IdentityIncomplete {
		return ""
	}
	return resolveWith(strings.TrimSpace(config.DeviceID), IdentitySourceConfig,
		dev.SerialNumber, dev.Hostname, dev.UserIdentity, dev.Platform, false).DeviceID
}

// IDForGuest gives the host/distro identity precedence over an inherited host
// config. Partial guest metadata falls back to the ordinary device identity.
func IDForGuest(dev model.Device, hostDeviceID, distroID string) string {
	if id := wslguest.DeviceID(hostDeviceID, distroID); id != "" {
		return id
	}
	return ID(dev)
}

// Gather collects device information (hostname, serial, OS version, user
// identity) and resolves the device identity (DeviceID) from the configured
// template or, by default, the machine identity. See identity.go.
func Gather(ctx context.Context, exec executor.Executor) model.Device {
	platform := exec.GOOS()
	hostname := getHostname(ctx, exec, platform)
	userIdentity := getDeveloperIdentity(exec)

	serial := SerialNumber(ctx, exec)
	var osVersion string
	switch platform {
	case model.PlatformWindows:
		osVersion = getOSVersionWindows(ctx, exec)
	case model.PlatformDarwin:
		osVersion = getOSVersion(ctx, exec)
	default: // linux and other unix
		osVersion = getOSVersionLinux(ctx, exec)
	}

	dev := model.Device{
		Hostname:     hostname,
		SerialNumber: serial,
		OSVersion:    osVersion,
		Platform:     platform,
		UserIdentity: userIdentity,
		Resources:    gatherResources(ctx, exec),
	}
	AttachIdentity(exec, &dev)
	return dev
}

var (
	idMu     sync.Mutex
	cachedID string
)

// SerialNumber resolves the machine identity (the device_id absent a
// configured override) once per process, so the run gate, scan, enforcers and
// hooks can't disagree. It runs before any network beacon. With no source it
// generates and persists an ID; an exhausted ctx or an ID that can't be
// persisted yields "unknown" (not cached, so a later caller retries).
func SerialNumber(ctx context.Context, exec executor.Executor) string {
	idMu.Lock()
	defer idMu.Unlock()
	if cachedID != "" {
		return cachedID
	}
	id := resolveID(ctx, exec)
	if usableSerial(id) {
		cachedID = id
	}
	return id
}

// ResetIDCache drops the process-wide identity. For tests.
func ResetIDCache() {
	idMu.Lock()
	defer idMu.Unlock()
	cachedID = ""
}

// probeSerial reports whether id came from the hardware rather than a
// per-install fallback (MachineGuid, /etc/machine-id).
func probeSerial(ctx context.Context, exec executor.Executor) (id string, hardware bool) {
	switch exec.GOOS() {
	case model.PlatformWindows:
		return getSerialNumberWindows(ctx, exec)
	case model.PlatformDarwin:
		return getSerialNumber(ctx, exec), true
	default: // linux and other unix
		return getSerialNumberLinux(ctx, exec)
	}
}

// darwinSCPrefsPath is where SystemConfiguration stores the names scutil
// reports. Reading it skips a subprocess; its layout is not a documented
// contract, so scutil remains the fallback.
const darwinSCPrefsPath = "/Library/Preferences/SystemConfiguration/preferences.plist"

type darwinSCPrefs struct {
	System struct {
		System struct {
			HostName string `plist:"HostName"`
		} `plist:"System"`
		Network struct {
			HostNames struct {
				LocalHostName string `plist:"LocalHostName"`
			} `plist:"HostNames"`
		} `plist:"Network"`
	} `plist:"System"`
}

// getHostname prefers the macOS configured names over os.Hostname: with no
// HostName set, macOS rewrites kern.hostname from DHCP or reverse DNS on every
// network change, so a VPN can turn "dev-mac" into "ip-10-0-1-5.ec2.internal".
func getHostname(ctx context.Context, exec executor.Executor, platform string) string {
	if platform == model.PlatformDarwin {
		if data, err := exec.ReadFile(darwinSCPrefsPath); err == nil {
			var prefs darwinSCPrefs
			if _, err := plist.Unmarshal(data, &prefs); err == nil {
				for _, name := range []string{prefs.System.System.HostName, prefs.System.Network.HostNames.LocalHostName} {
					if name = strings.TrimSpace(name); name != "" {
						return name
					}
				}
			}
		}
		for _, key := range []string{"HostName", "LocalHostName"} {
			stdout, _, exitCode, err := exec.RunWithTimeout(ctx, 10*time.Second, "scutil", "--get", key)
			if err == nil && exitCode == 0 {
				if name := strings.TrimSpace(stdout); name != "" {
					return name
				}
			}
		}
	}
	hostname, _ := exec.Hostname()
	return hostname
}

// getSerialNumberWindows and getOSVersionWindows are implemented in
// device_windows.go (native API) and device_other.go (stub).

func getSerialNumber(ctx context.Context, exec executor.Executor) string {
	// ioreg scoped to the platform device; "-l" dumps the whole registry (~MBs).
	stdout, _, _, err := exec.Run(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err == nil {
		for _, line := range strings.Split(stdout, "\n") {
			if strings.Contains(line, "IOPlatformSerialNumber") {
				parts := strings.Split(line, "=")
				if len(parts) >= 2 {
					serial := strings.TrimSpace(parts[1])
					serial = strings.Trim(serial, "\" ")
					if usableSerial(serial) {
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
					if usableSerial(serial) {
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

func getSerialNumberLinux(ctx context.Context, exec executor.Executor) (string, bool) {
	// /sys/class/dmi/id/product_serial is root-only (0400); user runs read the
	// value root persisted machine-wide instead (see resolveID).
	if data, err := exec.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
		s := strings.TrimSpace(string(data))
		if usableSerial(s) {
			return s, true
		}
	}

	// Fallback: dmidecode (requires root)
	stdout, _, _, err := exec.Run(ctx, "dmidecode", "-s", "system-serial-number")
	if err == nil {
		s := strings.TrimSpace(stdout)
		if usableSerial(s) {
			return s, true
		}
	}

	// Fallback: machine-id (always available, unique per install)
	if data, err := exec.ReadFile("/etc/machine-id"); err == nil {
		s := strings.TrimSpace(string(data))
		if usableSerial(s) {
			return s, false
		}
	}

	return "unknown", false
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
