//go:build windows

package launcher

import "golang.org/x/sys/windows/registry"

// runningVersionKey holds RunningVersion (updater-owned inventory) beside
// the MSI-owned AgentVersion, which is never written here.
const runningVersionKey = `Software\StepSecurity`

// SetRunningVersion writes HKLM\Software\StepSecurity\RunningVersion (64-bit
// view).
func SetRunningVersion(v string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runningVersionKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("RunningVersion", v)
}
