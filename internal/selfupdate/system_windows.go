//go:build windows

package selfupdate

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/step-security/dev-machine-guard/internal/winproc"
)

func prepareSmoke(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

// runSmokeCmd runs the self-check inside a kill-on-close job (spec S5 "in a
// job"): the child starts suspended, joins the job, then resumes, so
// nothing it spawns escapes; a timeout terminates the whole job, and
// closing the job on return (or on our own death) kills any leftovers.
func runSmokeCmd(cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("smoke job: %w", err)
	}
	defer func() { _ = windows.CloseHandle(job) }()
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return fmt.Errorf("smoke job limits: %w", err)
	}
	cmd.Cancel = func() error {
		if windows.TerminateJobObject(job, 1) == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	if err := winproc.StartInJob(cmd, job); err != nil {
		return fmt.Errorf("smoke job: %w", err)
	}
	return cmd.Wait()
}

// configFileSDDL matches `configure`'s icacls hardening: SYSTEM F,
// Administrators F, Users R, inheritance off.
const configFileSDDL = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"

const (
	maskFullAccess = 0x001F01FF
	maskRead       = 0x00120089
)

// EnsureConfigACL re-asserts the machine config.json DACL (D4: the SYSTEM
// updater trusts config.json only because users can't write it). It
// reports whether it had drifted. A missing file is not drift.
func EnsureConfigACL(path string) (bool, error) {
	fi, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	if ok, err := hasConfigACL(path); err != nil || ok {
		return false, err
	}
	sd, err := windows.SecurityDescriptorFromString(configFileSDDL)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return true, fmt.Errorf("set ACL on %s: %w", path, err)
	}
	return true, nil
}

func hasConfigACL(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("read ACL of %s: %w", path, err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount != 3 {
		return false, nil
	}
	want := map[windows.WELL_KNOWN_SID_TYPE]windows.ACCESS_MASK{
		windows.WinLocalSystemSid:           maskFullAccess,
		windows.WinBuiltinAdministratorsSid: maskFullAccess,
		windows.WinBuiltinUsersSid:          maskRead,
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matched := false
		for kind, mask := range want {
			if sid.IsWellKnown(kind) && ace.Mask == mask {
				delete(want, kind)
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	return len(want) == 0, nil
}

// SetRunningVersion writes HKLM\Software\StepSecurity\RunningVersion. The
// MSI-owned AgentVersion value is never touched.
func SetRunningVersion(v string) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, `Software\StepSecurity`,
		registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("RunningVersion", v)
}

// FreeBytes reports the bytes available to this process on path's volume.
func FreeBytes(path string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &total, &free); err != nil {
		return 0, err
	}
	return avail, nil
}

// InstallerBusy reports a Windows Installer transaction in progress: the
// Global\_MSIExecute mutex exists while msiexec runs an install.
func InstallerBusy() bool {
	name, err := windows.UTF16PtrFromString(`Global\_MSIExecute`)
	if err != nil {
		return false
	}
	h, err := windows.OpenMutex(windows.SYNCHRONIZE, false, name)
	if err != nil {
		return false
	}
	_ = windows.CloseHandle(h)
	return true
}
