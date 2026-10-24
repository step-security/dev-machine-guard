//go:build windows

package detector

import (
	"context"
	"math"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows/registry"
)

const uninstallKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`

// readARPEntries reads every Uninstall subkey from HKLM (64- and 32-bit
// views) and HKCU. The scan runs as the interactive user, so HKCU is that
// user's hive.
func readARPEntries(ctx context.Context, _ executor.Executor) []arpEntry {
	var out []arpEntry
	for _, src := range []struct {
		root   registry.Key
		hive   string
		view   string
		access uint32
	}{
		{registry.LOCAL_MACHINE, "HKLM", "64", registry.WOW64_64KEY},
		{registry.LOCAL_MACHINE, "HKLM", "32", registry.WOW64_32KEY},
		{registry.CURRENT_USER, "HKCU", "", 0},
	} {
		if ctx.Err() != nil {
			break
		}
		out = append(out, readUninstallKey(src.root, src.hive, src.view, src.access)...)
	}
	return out
}

func readUninstallKey(root registry.Key, hive, view string, access uint32) []arpEntry {
	k, err := registry.OpenKey(root, uninstallKeyPath, registry.ENUMERATE_SUB_KEYS|access)
	if err != nil {
		return nil
	}
	names, err := k.ReadSubKeyNames(-1)
	_ = k.Close()
	if err != nil {
		return nil
	}
	out := make([]arpEntry, 0, len(names))
	for _, name := range names {
		sk, err := registry.OpenKey(root, uninstallKeyPath+`\`+name, registry.QUERY_VALUE|access)
		if err != nil {
			continue
		}
		e := arpEntry{KeyName: name, Hive: hive, View: view}
		e.DisplayName, _, _ = sk.GetStringValue("DisplayName")
		e.DisplayVersion, _, _ = sk.GetStringValue("DisplayVersion")
		e.Publisher, _, _ = sk.GetStringValue("Publisher")
		e.InstallLocation, _, _ = sk.GetStringValue("InstallLocation")
		e.InstallDate, _, _ = sk.GetStringValue("InstallDate")
		e.URLInfoAbout, _, _ = sk.GetStringValue("URLInfoAbout")
		e.ParentKeyName, _, _ = sk.GetStringValue("ParentKeyName")
		e.ReleaseType, _, _ = sk.GetStringValue("ReleaseType")
		if v, _, err := sk.GetIntegerValue("SystemComponent"); err == nil {
			e.SystemComponent = v == 1
		}
		if v, _, err := sk.GetIntegerValue("WindowsInstaller"); err == nil {
			e.WindowsInstaller = v == 1
		}
		if v, _, err := sk.GetIntegerValue("EstimatedSize"); err == nil && v <= math.MaxUint32 {
			e.EstimatedSizeKB = uint32(v)
		}
		_ = sk.Close()
		out = append(out, e)
	}
	return out
}
