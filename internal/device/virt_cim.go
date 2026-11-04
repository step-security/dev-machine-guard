package device

import (
	"context"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// windowsSMBIOSFromCIM asks CIM for the manufacturer and model. Used when the
// registry mirror is missing, and by the non-Windows stub.
func windowsSMBIOSFromCIM(ctx context.Context, exec executor.Executor) smbiosInfo {
	var info smbiosInfo
	if out, _, _, err := exec.RunWithTimeout(ctx, imdsTimeout, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).Manufacturer"); err == nil {
		info.Manufacturer = strings.TrimSpace(out)
	}
	if out, _, _, err := exec.RunWithTimeout(ctx, imdsTimeout, "powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_ComputerSystem).Model"); err == nil {
		info.Product = strings.TrimSpace(out)
	}
	return info
}
