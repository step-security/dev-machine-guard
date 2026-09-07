package device

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// Registry locations and service names for WSL, shared by the native
// (wsl_windows.go) and exec-fallback (wsl_other.go) inventory probes.
const (
	// lxssUserSubpath is appended to a per-user hive root (HKCU, or an
	// HKU\<SID> root) to reach the authoritative per-user distro index.
	lxssUserSubpath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss`

	// wslFlagVM is the undocumented Flags bit set when a distro runs under
	// WSL2 (microsoft/WSL#4251). Both measured: Flags 0x7 = WSL1, 0xF = WSL2.
	// The per-distro Version DWORD is NOT usable — it reads 2 even on WSL1.
	wslFlagVM uint64 = 0x8
)

// wslServiceNames are the two service keys under
// HKLM\SYSTEM\CurrentControlSet\Services that indicate WSL is installed:
// WslService for the Microsoft Store / MSI build (current), LxssManager for
// the legacy inbox component. System32\wsl.exe is deliberately NOT a signal —
// it ships with stock Windows even when WSL is fully disabled.
var wslServiceNames = []string{"WslService", "LxssManager"}

// wslRunningTimeout bounds the one subprocess this detector makes. `wsl.exe
// --list --running --quiet` queries wslservice for the active set; it does not
// start a distribution, but it can hang if the service is wedged.
const wslRunningTimeout = 8 * time.Second

// GatherWSL detects Windows Subsystem for Linux on the host. It returns nil on
// non-Windows platforms — WSL detection is host-side only; the Linux binary
// runs inside a distro and identifies itself separately. It never errors:
// every failure degrades to WSLPresenceUnknown so a partial probe can't read
// as a confident "no WSL".
func GatherWSL(ctx context.Context, exec executor.Executor) *model.WSLInfo {
	if exec.GOOS() != model.PlatformWindows {
		return nil
	}
	return gatherWSLWindows(ctx, exec)
}

// gatherWSLWindows orchestrates the Windows probe. The registry inventory and
// service/version primitives are platform-split (native registry API vs
// reg.exe); the running-distro probe is a plain wsl.exe call shared by both.
func gatherWSLWindows(ctx context.Context, exec executor.Executor) *model.WSLInfo {
	distros, invOK := wslRegistryInventory(exec)
	installed, svcOK := wslServiceInstalled(exec)

	info := &model.WSLInfo{
		Installed: installed,
		Version:   "unknown",
		Distros:   distros,
	}

	switch {
	case installed || len(distros) > 0:
		info.Presence = model.WSLPresenceYes
	case !invOK && !svcOK:
		// Neither probe could read anything conclusive (e.g. registry access
		// denied). Don't claim "no WSL".
		info.Presence = model.WSLPresenceUnknown
	default:
		info.Presence = model.WSLPresenceNo
	}

	if info.Presence != model.WSLPresenceYes {
		return info
	}

	if v := wslPackageVersion(ctx, exec); v != "" {
		info.Version = v
	}

	// "Actively used" — only worth a subprocess when WSL is installed, at least
	// one distro is registered, and a WSL service is actually running.
	if installed && len(distros) > 0 && wslMayHaveRunningDistro(exec) {
		running := wslRunningDistros(ctx, exec)
		for i := range info.Distros {
			if running[info.Distros[i].Name] {
				info.Distros[i].Running = true
				info.Active = true
			}
		}
	}

	return info
}

// wslMayHaveRunningDistro reports whether the running-distro probe is worth its
// subprocess. It answers from service state alone, via a native query that
// spawns nothing: the WSL services manage every distro, so if neither is
// running then nothing can be.
//
// This is not just about saving a process. `wsl.exe --list --running --quiet`
// *starts* WslService when it is stopped (measured: Stopped before, Running
// after, empty output) — so on a machine where WSL is installed but unused
// since boot, probing wakes a Windows service to learn that nothing is running.
//
// An unknown service state answers true: we would rather pay for the probe than
// under-report "active".
func wslMayHaveRunningDistro(exec executor.Executor) bool {
	running, known := wslServiceRunning(exec)
	return !known || running
}

// wslRunningDistros returns the set of distribution names WSL reports as
// running. Empty on any failure (an absent set is indistinguishable from "none
// running", and both mean "not active"). Handles wsl.exe's default UTF-16LE
// output, which dmg cannot switch to UTF-8 (that needs WSL_UTF8 in the child
// env, and the executor has no env seam).
func wslRunningDistros(ctx context.Context, exec executor.Executor) map[string]bool {
	stdout, _, _, err := exec.RunWithTimeout(ctx, wslRunningTimeout, "wsl.exe", "--list", "--running", "--quiet")
	if err != nil {
		return nil
	}
	out := make(map[string]bool)
	for _, line := range strings.Split(decodeWinCLI(stdout), "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			out[name] = true
		}
	}
	return out
}

// decodeWinCLI normalizes output from Windows console tools that emit UTF-16LE.
// wsl.exe writes UTF-16LE with no BOM unless WSL_UTF8=1 is set in its
// environment (WSL >=0.64.0), which dmg cannot do. A stream with interleaved
// NUL bytes is decoded as UTF-16LE; anything else (UTF-8 from a newer WSL or an
// already-clean string) is returned unchanged. A stray CR is stripped.
func decodeWinCLI(s string) string {
	b := []byte(s)
	if !bytes.ContainsRune(b, 0) {
		return strings.ReplaceAll(s, "\r", "")
	}
	if len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE { // strip UTF-16LE BOM
		b = b[2:]
	}
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return strings.ReplaceAll(string(utf16.Decode(u)), "\r", "")
}

// wslVersionFromFlags maps the registry Flags value to a WSL version. See
// wslFlagVM for the reliability caveat.
func wslVersionFromFlags(flags uint64) int {
	if flags&wslFlagVM != 0 {
		return 2
	}
	return 1
}

// sortDistros gives the inventory a stable order (default first, then by name)
// so output and telemetry don't churn between runs over a registry-enumeration
// order that isn't guaranteed.
func sortDistros(d []model.WSLDistro) {
	sort.SliceStable(d, func(i, j int) bool {
		if d[i].Default != d[j].Default {
			return d[i].Default
		}
		return d[i].Name < d[j].Name
	})
}
