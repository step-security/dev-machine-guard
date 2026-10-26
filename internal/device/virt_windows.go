//go:build windows

package device

import (
	"context"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows/registry"
)

// windowsSMBIOS reads the firmware strings from the registry mirror of the
// SMBIOS tables (no subprocess), falling back to CIM when the key is absent.
func windowsSMBIOS(ctx context.Context, exec executor.Executor) smbiosInfo {
	var info smbiosInfo
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE); err == nil {
		info.Manufacturer, _, _ = k.GetStringValue("SystemManufacturer")
		info.Product, _, _ = k.GetStringValue("SystemProductName")
		info.BIOSVendor, _, _ = k.GetStringValue("BIOSVendor")
		_ = k.Close()
	}
	if info.Manufacturer == "" && info.Product == "" {
		return windowsSMBIOSFromCIM(ctx, exec)
	}
	return info
}
