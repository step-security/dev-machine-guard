//go:build windows

package device

import (
	"context"
	"fmt"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// getSerialNumberWindows reads the BIOS serial number.
// Tries native registry first, then PowerShell WMI (for VMs where the registry
// key may not exist), then falls back to MachineGuid.
func getSerialNumberWindows(ctx context.Context, exec executor.Executor) string {
	// Try BIOS registry key (fastest, no subprocess)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err == nil {
		serial, _, err := k.GetStringValue("SystemSerialNumber")
		_ = k.Close()
		if err == nil && serial != "" && serial != "System Serial Number" && serial != "To Be Filled By O.E.M." {
			return serial
		}
	}

	// Fallback: PowerShell WMI query (works on EC2 and other VMs where
	// the registry key doesn't exist but WMI exposes the serial)
	stdout, _, _, err := exec.Run(ctx, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance -ClassName Win32_BIOS).SerialNumber")
	if err == nil {
		s := strings.TrimSpace(stdout)
		if s != "" {
			return s
		}
	}

	// Last resort: MachineGuid (unique per install, always present)
	k, err = registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err == nil {
		guid, _, err := k.GetStringValue("MachineGuid")
		_ = k.Close()
		if err == nil && guid != "" {
			return guid
		}
	}

	return "unknown"
}

// getOSVersionWindows returns the Windows version using the native RtlGetVersion API.
func getOSVersionWindows(_ context.Context, _ executor.Executor) string {
	v := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
}
