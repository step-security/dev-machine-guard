//go:build windows

package updatestate

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// DataRoot is <ProgramData>\StepSecurity, from the ProgramData known folder.
func DataRoot() string {
	pd, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || pd == "" {
		pd = os.Getenv("ProgramData") // the known folder can't fail on a working system
	}
	return filepath.Join(pd, "StepSecurity")
}

// trustedInstallerSID is NT SERVICE\TrustedInstaller, owner of
// C:\Program Files and the system drive's root.
const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

const (
	aceInheritOnly = 0x08 // INHERIT_ONLY_ACE: doesn't apply to the object itself
	aceAllowed     = 0    // ACCESS_ALLOWED_ACE_TYPE
	aceDenied      = 1    // ACCESS_DENIED_ACE_TYPE

	// rootWriteMask: rights that let a holder change the root's contents
	// or its ACL. ancestorWriteMask: rights on an ancestor that let a
	// holder replace or re-ACL what's beneath it (adding new entries,
	// FILE_ADD_SUBDIRECTORY on a drive root, is harmless).
	rootWriteMask     = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
	ancestorWriteMask = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000
)

func trustedSID(s *windows.SID) bool {
	return s != nil && (s.IsWellKnown(windows.WinLocalSystemSid) ||
		s.IsWellKnown(windows.WinBuiltinAdministratorsSid) || s.String() == trustedInstallerSID)
}

// checkRootProtected requires root, and every ancestor, to be owned by
// SYSTEM, Administrators or TrustedInstaller, and grants no one else write
// access to root, or rights over an ancestor that would let them swap root.
func checkRootProtected(root string) error {
	mask := uint32(rootWriteMask)
	for p := filepath.Clean(root); ; p = filepath.Dir(p) {
		if err := checkDirACL(p, mask); err != nil {
			return err
		}
		if filepath.Dir(p) == p {
			return nil
		}
		mask = ancestorWriteMask
	}
}

func checkDirACL(path string, mask uint32) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read ACL of %s: %w", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || !trustedSID(owner) {
		return fmt.Errorf("%s is owned by %v, not SYSTEM/Administrators/TrustedInstaller", path, owner)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read DACL of %s: %w", path, err)
	}
	if acl == nil {
		return fmt.Errorf("%s has a NULL DACL", path)
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return fmt.Errorf("read ACE %d of %s: %w", i, path, err)
		}
		if ace.Header.AceFlags&aceInheritOnly != 0 || ace.Header.AceType == aceDenied || uint32(ace.Mask)&mask == 0 {
			continue
		}
		if ace.Header.AceType != aceAllowed {
			return fmt.Errorf("%s has an ACE of type %d granting %#x", path, ace.Header.AceType, ace.Mask)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trustedSID(sid) {
			return fmt.Errorf("%s grants %s write access (%#x)", path, sid, ace.Mask)
		}
	}
	return nil
}
