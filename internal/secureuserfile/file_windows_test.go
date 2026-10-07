//go:build windows

package secureuserfile

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func normalizeSecureTestUser(t *testing.T, u *user.User) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(u.HomeDir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		t.Fatalf("temporary home owner: %v", err)
	}
	u.Uid = owner.String()
}

func assertWindowsOwner(t *testing.T, path string, want *windows.SID) {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%q): %v", path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		t.Fatalf("owner(%q): %v", path, err)
	}
	if !owner.Equals(want) {
		t.Fatalf("owner(%q) = %s, want %s", path, owner.String(), want.String())
	}
}

func TestReopenSecurityHandle_FromRootFile(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	file, err := root.OpenFile("config", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	handle, err := reopenSecurityHandle(file, windows.READ_CONTROL)
	if err != nil {
		t.Fatalf("reopenSecurityHandle: %v", err)
	}
	windows.CloseHandle(handle)
}

func TestSecureUserFile_CreatedParentsHaveRestrictedACL(t *testing.T) {
	home := t.TempDir()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = home
	h, err := openHome(current)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if err := h.EnsureParent(filepath.Join(".config", "tool", "config")); err != nil {
		t.Fatalf("ensureParent: %v", err)
	}

	targetSID, err := windows.StringToSid(current.Uid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(home, ".config"), filepath.Join(home, ".config", "tool")} {
		assertWindowsOwner(t, path, targetSID)
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatalf("GetNamedSecurityInfo(%q): %v", path, err)
		}
		control, _, err := descriptor.Control()
		if err != nil {
			t.Fatal(err)
		}
		if control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("%q inherits a broad parent ACL", path)
		}
		acl, _, err := descriptor.DACL()
		if err != nil {
			t.Fatal(err)
		}
		if acl == nil || acl.AceCount < 2 {
			t.Fatalf("%q ACL = %v, want target user and SYSTEM entries", path, acl)
		}
		seenTarget, seenSystem := false, false
		for i := uint32(0); i < uint32(acl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, i, &ace); err != nil {
				t.Fatal(err)
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
				t.Fatalf("%q contains a non-explicit allow ACE", path)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			switch {
			case sid.Equals(targetSID):
				seenTarget = true
			case sid.Equals(systemSID):
				seenSystem = true
			default:
				t.Fatalf("%q ACL grants access to unexpected SID %s", path, sid.String())
			}
		}
		if !seenTarget || !seenSystem {
			t.Fatalf("%q ACL does not contain only target user and SYSTEM", path)
		}
	}

	file := openSecureTestFile(t, h, filepath.Join(".config", "tool", "config"))
	if err := file.Commit([]byte("managed\n"), FileMode); err != nil {
		t.Fatal(err)
	}
	assertWindowsOwner(t, file.Location(), targetSID)
}

func TestSecureUserFile_RepairsOnlyPreexistingManagedParentACL(t *testing.T) {
	home := t.TempDir()
	ancestor := filepath.Join(home, "AppData", "Roaming")
	parent := filepath.Join(ancestor, "pip")
	if err := os.MkdirAll(parent, ParentMode); err != nil {
		t.Fatal(err)
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = home
	normalizeSecureTestUser(t, current)
	h, err := openHome(current)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	targetSID, err := windows.StringToSid(current.Uid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	everyoneSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		secureExplicitAccess(targetSID, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, windows.TRUSTEE_IS_USER),
		secureExplicitAccess(systemSID, windows.GENERIC_ALL, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		secureExplicitAccess(everyoneSID, windows.GENERIC_READ, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ancestor, parent} {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
			t.Fatal(err)
		}
	}

	if err := h.EnsureParent(filepath.Join("AppData", "Roaming", "pip", "pip.ini")); err != nil {
		t.Fatalf("EnsureParent: %v", err)
	}
	ancestorFile, err := os.Open(ancestor)
	if err != nil {
		t.Fatal(err)
	}
	secure, err := h.MetadataSecure(ancestorFile, ParentMode)
	_ = ancestorFile.Close()
	if err != nil || secure {
		t.Fatalf("ancestor metadata = %v, %v, want unchanged broad ACL", secure, err)
	}
	file, err := os.Open(parent)
	if err != nil {
		t.Fatal(err)
	}
	secure, err = h.MetadataSecure(file, ParentMode)
	_ = file.Close()
	if err != nil || !secure {
		t.Fatalf("upgraded parent metadata = %v, %v, want secure", secure, err)
	}
}

func TestSecureUserFile_RejectsWeakExpectedPrincipalACL(t *testing.T) {
	home := t.TempDir()
	h := newSecureTestHome(t, home)
	file := openSecureTestFile(t, h, "config")
	if err := file.Commit([]byte("managed\n"), FileMode); err != nil {
		t.Fatal(err)
	}
	targetSID, err := windows.StringToSid(h.targetUser.Uid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		secureExplicitAccess(targetSID, windows.GENERIC_READ, windows.NO_INHERITANCE, windows.TRUSTEE_IS_USER),
		secureExplicitAccess(systemSID, windows.GENERIC_READ, windows.NO_INHERITANCE, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		file.Location(),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if secure, err := file.MetadataSecure(FileMode); err != nil || secure {
		t.Fatalf("MetadataSecure with read-only target and SYSTEM ACEs = %v, %v, want false", secure, err)
	}
}

func TestSecureUserFile_PreexistingWrongOwnerRejected(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "config")
	if err := os.WriteFile(path, []byte("existing\n"), FileMode); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	originalOwner, _, err := descriptor.Owner()
	if err != nil || originalOwner == nil {
		t.Fatalf("original owner: %v", err)
	}
	targetSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if originalOwner.Equals(targetSID) {
		t.Skip("test object is already owned by SYSTEM")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	current.HomeDir = home
	current.Uid = targetSID.String()
	h, err := openHome(current)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	before := windowsSecurityDescriptor(t, path)
	file := openSecureTestFile(t, h, "config")
	if _, _, _, err := file.Read(); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("Read error = %v, want ErrTargetUnusable", err)
	}
	if err := file.RepairMetadata(FileMode); !errors.Is(err, ErrTargetUnusable) {
		t.Fatalf("RepairMetadata error = %v, want ErrTargetUnusable", err)
	}
	if after := windowsSecurityDescriptor(t, path); after != before {
		t.Fatalf("wrong-owner descriptor changed: %s -> %s", before, after)
	}
	assertWindowsOwner(t, path, originalOwner)
}

// setModifyOnlyACL gives path the shape a legacy object can have: the target
// user holds Modify (0x1301bf: no WRITE_DAC or WRITE_OWNER), not Full Control,
// so only the owner's implicit READ_CONTROL|WRITE_DAC can change its permissions.
func setModifyOnlyACL(t *testing.T, h *Home, path string, directory bool) {
	t.Helper()
	flags := ""
	if directory {
		flags = "OICI"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;" + flags + ";0x1301bf;;;" + h.targetUser.Uid + ")(A;" + flags + ";FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func windowsSecurityDescriptor(t *testing.T, path string) string {
	t.Helper()
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%q): %v", path, err)
	}
	return descriptor.String()
}

func requireOwnerAssignmentDenied(t *testing.T, h *Home, path string, directory bool) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := applySecureMetadata(h, f, FileMode, directory); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("owner-assigning metadata on Modify-only %q = %v, want access denied", path, err)
	}
}

func requireSecurePath(t *testing.T, h *Home, path string, mode os.FileMode) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if secure, err := h.MetadataSecure(f, mode); err != nil || !secure {
		t.Fatalf("metadata %q = %v, %v, want secure", path, secure, err)
	}
}

func TestSecureUserFile_RepairWithoutOwnershipRights(t *testing.T) {
	home := t.TempDir()
	h := newSecureTestHome(t, home)
	probe := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(probe, nil, FileMode); err != nil {
		t.Fatal(err)
	}
	setModifyOnlyACL(t, h, probe, false)
	if f, err := os.Open(probe); err != nil {
		t.Fatal(err)
	} else {
		err = applySecureMetadata(h, f, FileMode, false)
		_ = f.Close()
		if err == nil {
			t.Skip("this token can assign ownership without WRITE_OWNER; run as a standard user")
		}
	}
	targetSID, err := windows.StringToSid(h.targetUser.Uid)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, ".stepsecurity")
	if err := os.Mkdir(dir, ParentMode); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	lockPath := statePath + ".lock"
	original := []byte(`{"schema_version":1}` + "\n")
	for _, path := range []string{statePath, lockPath} {
		if err := os.WriteFile(path, original, FileMode); err != nil {
			t.Fatal(err)
		}
		setModifyOnlyACL(t, h, path, false)
		requireOwnerAssignmentDenied(t, h, path, false)
	}
	setModifyOnlyACL(t, h, dir, true)
	requireOwnerAssignmentDenied(t, h, dir, true)

	if err := h.EnsureParent(filepath.Join(".stepsecurity", "state.json")); err != nil {
		t.Fatalf("EnsureParent on Modify-only parent: %v", err)
	}
	requireSecurePath(t, h, dir, ParentMode)

	state := openSecureTestFile(t, h, filepath.Join(".stepsecurity", "state.json"))
	if err := state.RepairMetadata(FileMode); err != nil {
		t.Fatalf("RepairMetadata on Modify-only file: %v", err)
	}
	requireSecurePath(t, h, statePath, FileMode)

	lockFile := openSecureTestFile(t, h, filepath.Join(".stepsecurity", "state.json.lock"))
	lock, err := lockFile.OpenLock()
	if err != nil {
		t.Fatalf("OpenLock on Modify-only lock: %v", err)
	}
	_ = lock.Close()
	requireSecurePath(t, h, lockPath, FileMode)

	for _, path := range []string{dir, statePath, lockPath} {
		assertWindowsOwner(t, path, targetSID)
	}
	for _, path := range []string{statePath, lockPath} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("%q bytes = %q, %v, want unchanged", path, got, err)
		}
	}

	before := windowsSecurityDescriptor(t, statePath)
	if err := state.RepairMetadata(FileMode); err != nil {
		t.Fatalf("RepairMetadata on secure file: %v", err)
	}
	if after := windowsSecurityDescriptor(t, statePath); after != before {
		t.Fatalf("secure file descriptor changed: %s -> %s", before, after)
	}

	absent := openSecureTestFile(t, h, filepath.Join(".stepsecurity", "absent.json"))
	if err := absent.RepairMetadata(FileMode); err != nil {
		t.Fatalf("RepairMetadata on absent file: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "absent.json")); !os.IsNotExist(err) {
		t.Fatalf("absent file created: %v", err)
	}
}
