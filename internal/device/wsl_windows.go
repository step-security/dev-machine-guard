//go:build windows

package device

import (
	"context"
	"errors"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// wslWellKnownSIDs are the pseudo-accounts whose hives carry a seeded-but-empty
// Lxss key. They must be skipped: a SYSTEM-context scan finds Lxss present
// under S-1-5-18 with zero distros, which would otherwise read as "WSL absent".
// Real distros live under interactive users' SIDs (S-1-5-21-...).
var wslWellKnownSIDs = map[string]bool{
	".DEFAULT": true,
	"S-1-5-18": true, // LocalSystem
	"S-1-5-19": true, // LocalService
	"S-1-5-20": true, // NetworkService
}

// wslRegistryInventory enumerates every loaded user hive under HKU and reads
// its Lxss distro index. Enumerating HKU (rather than just HKCU) is what lets a
// SYSTEM-context run still see a logged-in user's distros. Users whose hive is
// not loaded (never signed in this boot) are invisible — a documented limit, we
// do not load NTUSER.DAT. The bool is false only when HKU itself can't be read.
func wslRegistryInventory(_ executor.Executor) ([]model.WSLDistro, bool) {
	users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, false
	}
	defer users.Close()

	sids, err := users.ReadSubKeyNames(-1)
	if err != nil {
		return nil, false
	}

	var distros []model.WSLDistro
	for _, sid := range sids {
		if wslWellKnownSIDs[sid] || strings.HasSuffix(sid, "_Classes") {
			continue
		}
		distros = append(distros, readLxssForSID(sid)...)
	}
	sortDistros(distros)
	return distros, true
}

// readLxssForSID reads the distros registered under one user hive. Missing keys
// (the common case — most SIDs have no WSL) yield nothing, not an error.
func readLxssForSID(sid string) []model.WSLDistro {
	root, err := registry.OpenKey(registry.USERS, sid+`\`+lxssUserSubpath, registry.READ)
	if err != nil {
		return nil
	}
	defer root.Close()

	defaultGUID, _, _ := root.GetStringValue("DefaultDistribution")

	guids, err := root.ReadSubKeyNames(-1)
	if err != nil {
		return nil
	}

	var out []model.WSLDistro
	for _, guid := range guids {
		dk, err := registry.OpenKey(registry.USERS, sid+`\`+lxssUserSubpath+`\`+guid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		name, _, _ := dk.GetStringValue("DistributionName")
		flags, _, _ := dk.GetIntegerValue("Flags")
		basePath, _, _ := dk.GetStringValue("BasePath")
		// DefaultUid is absent on some registrations, and 0 (root) is a
		// meaningful answer — so read the error rather than defaulting to 0.
		var defaultUID *uint32
		if uid, _, err := dk.GetIntegerValue("DefaultUid"); err == nil {
			u := uint32(uid)
			defaultUID = &u
		}
		dk.Close()

		if name == "" {
			continue
		}
		out = append(out, model.WSLDistro{
			Name:       name,
			DistroID:   guid,
			WSLVersion: wslVersionFromFlags(flags),
			Default:    guid == defaultGUID,
			OwnerSID:   sid,
			BasePath:   basePath,
			DefaultUID: defaultUID,
		})
	}
	return out
}

// wslServiceInstalled reports whether a WSL runtime service is registered. The
// LOCAL_MACHINE services hive is always readable, so an absent key is a
// confident "not installed" — the bool is true whenever we could look.
func wslServiceInstalled(_ executor.Executor) (bool, bool) {
	for _, svc := range wslServiceNames {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+svc, registry.QUERY_VALUE)
		if err == nil {
			k.Close()
			return true, true
		}
	}
	return false, true
}

// wslServiceRunning reports whether either WSL runtime service is currently in
// the RUNNING state, without spawning anything.
//
// It asks for SC_MANAGER_CONNECT on the manager and SERVICE_QUERY_STATUS on the
// service — exactly the rights the default WSL service ACL grants Interactive
// Users (verified from its SDDL), so this works for a non-admin agent. It
// deliberately does not use mgr.Connect(), which requests full access and would
// need admin.
//
// known is false when we could not tell: the SCM would not open, or a service
// that may exist could not be queried. A service that is genuinely absent
// (ERROR_SERVICE_DOES_NOT_EXIST) is a conclusive "not running", not an unknown.
func wslServiceRunning(_ executor.Executor) (bool, bool) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(scm)

	known := true
	for _, svc := range wslServiceNames {
		name, err := windows.UTF16PtrFromString(svc)
		if err != nil {
			known = false
			continue
		}
		h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
		if err != nil {
			// Absent is an answer; anything else means we could not look.
			if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
				known = false
			}
			continue
		}
		var status windows.SERVICE_STATUS
		err = windows.QueryServiceStatus(h, &status)
		windows.CloseServiceHandle(h)
		if err != nil {
			known = false
			continue
		}
		if status.CurrentState == windows.SERVICE_RUNNING {
			return true, true
		}
	}
	return false, known
}

// wslPackageVersion reads the installed WSL version from the Uninstall registry
// entry the MSI/Store build writes ("Windows Subsystem for Linux"). Returns ""
// (caller floors to "unknown") when undeterminable.
func wslPackageVersion(_ context.Context, _ executor.Executor) string {
	roots := []struct {
		key  registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
	}
	for _, r := range roots {
		parent, err := registry.OpenKey(r.key, r.path, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subs, err := parent.ReadSubKeyNames(-1)
		parent.Close()
		if err != nil {
			continue
		}
		for _, sub := range subs {
			sk, err := registry.OpenKey(r.key, r.path+`\`+sub, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			name, _, _ := sk.GetStringValue("DisplayName")
			if strings.EqualFold(strings.TrimSpace(name), "Windows Subsystem for Linux") {
				ver, _, _ := sk.GetStringValue("DisplayVersion")
				sk.Close()
				if v := strings.TrimSpace(ver); v != "" {
					return v
				}
				continue
			}
			sk.Close()
		}
	}
	return ""
}
