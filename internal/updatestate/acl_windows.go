//go:build windows

package updatestate

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protectedDirSDDL: owner SYSTEM; protected DACL (no inheritance from the
// parent) granting SYSTEM and Administrators full control and Users
// read+execute, each inherited by subdirectories and files.
const protectedDirSDDL = "O:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"

const (
	fileAllAccess   windows.ACCESS_MASK = 0x001F01FF // FA
	fileReadExecute windows.ACCESS_MASK = 0x001200A9 // RX
	inheritOICI                         = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
)

// EnsureProtectedDir creates path if missing and makes its owner SYSTEM and
// its DACL protected: SYSTEM F, Administrators F, Users RX, inherited by
// children. It reports whether an existing directory had drifted and was
// fixed; creating the directory is not drift. Re-applying the DACL
// propagates it to children that inherit. Needs SYSTEM or an elevated
// administrator (setting another principal as owner takes
// SeRestorePrivilege, which is enabled for the call). The parent must exist
// and is trusted not to be writable by non-admins.
func EnsureProtectedDir(path string) (fixed bool, err error) {
	err = withOwnerPrivileges(func() error {
		exists, err := checkDirNotReparse(path)
		if err != nil {
			return err
		}
		if !exists {
			err = createProtectedDir(path)
			if !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
				return err
			}
			if _, err = checkDirNotReparse(path); err != nil {
				return err
			}
		}
		ok, err := hasProtectedACL(path)
		if err != nil || ok {
			return err
		}
		fixed = true
		return applyProtectedACL(path)
	})
	return fixed, err
}

func createProtectedDir(path string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedDirSDDL)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	return windows.CreateDirectory(p, &sa)
}

func applyProtectedACL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(protectedDirSDDL)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("updatestate: set ACL on %s: %w", path, err)
	}
	return nil
}

// hasProtectedACL reports whether path has exactly the wanted owner and
// protected DACL.
func hasProtectedACL(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("updatestate: read ACL of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return false, nil
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
		windows.WinLocalSystemSid:           fileAllAccess,
		windows.WinBuiltinAdministratorsSid: fileAllAccess,
		windows.WinBuiltinUsersSid:          fileReadExecute,
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return false, nil
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != inheritOICI {
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

// withOwnerPrivileges runs fn on a dedicated OS thread impersonating the
// process token with SeRestorePrivilege and SeTakeOwnershipPrivilege enabled
// where held. The thread is never unlocked, so the runtime discards it (and
// any impersonation) when the goroutine exits.
func withOwnerPrivileges(fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err == nil {
			defer func() { _ = windows.RevertToSelf() }()
			enableThreadPrivileges("SeRestorePrivilege", "SeTakeOwnershipPrivilege")
		}
		done <- fn()
	}()
	return <-done
}

func enableThreadPrivileges(names ...string) {
	var tok windows.Token
	if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &tok) != nil {
		return
	}
	defer tok.Close()
	for _, name := range names {
		var luid windows.LUID
		p, err := windows.UTF16PtrFromString(name)
		if err != nil || windows.LookupPrivilegeValue(nil, p, &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	}
}
