// Package fwpath is the single source of truth for where the Windows on-device
// firewall (the StepSecurityOnDeviceFirewall service) lives on disk. It is a
// leaf package (stdlib and x/sys only) because the GUI launcher imports it:
// the MSI's stop-for-msi helper must leave the firewall's process alone.
package fwpath

import "path/filepath"

const (
	// DirName is the firewall's folder under %ProgramFiles%\StepSecurity, the
	// location the PowerShell loader uses too ($FIREWALL_DIR).
	DirName = "OnDeviceFirewall"
	// ExeName is the firewall exe the service runs.
	ExeName = "stepsecurity-ondevice-firewall.exe"
)

// Dir is %ProgramFiles%\StepSecurity\OnDeviceFirewall ("" off Windows).
func Dir() string {
	pf := programFiles()
	if pf == "" {
		return ""
	}
	return filepath.Join(pf, "StepSecurity", DirName)
}

// Exe is the installed firewall exe, Dir()\ExeName ("" off Windows).
func Exe() string {
	d := Dir()
	if d == "" {
		return ""
	}
	return filepath.Join(d, ExeName)
}

// DataDir is %ProgramData%\StepSecurity\OnDeviceFirewall, the firewall's own
// logs and status ("" off Windows). Removing the firewall removes it.
func DataDir() string {
	pd := programData()
	if pd == "" {
		return ""
	}
	return filepath.Join(pd, "StepSecurity", DirName)
}
