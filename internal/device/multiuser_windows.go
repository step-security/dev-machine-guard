//go:build windows

package device

import "golang.org/x/sys/windows/registry"

// readWindowsEdition reports the edition id and whether the Remote Desktop
// Session Host role is installed, both from the registry. Failures read as
// "no evidence" rather than errors: the other rules still apply.
func readWindowsEdition() (edition string, tsAppCompat bool) {
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringValue("EditionID"); err == nil {
			edition = v
		}
		_ = k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetIntegerValue("TSAppCompat"); err == nil && v == 1 {
			tsAppCompat = true
		}
		_ = k.Close()
	}
	return edition, tsAppCompat
}
