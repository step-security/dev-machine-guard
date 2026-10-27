//go:build windows

package updatestate

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func requireElevated(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated (administrator) process")
	}
}

func TestEnsureProtectedDir(t *testing.T) {
	requireElevated(t)
	dir := filepath.Join(t.TempDir(), "versions")

	fixed, err := EnsureProtectedDir(dir)
	if err != nil || fixed {
		t.Fatalf("create: fixed=%v err=%v", fixed, err)
	}
	if ok, err := hasProtectedACL(dir); !ok || err != nil {
		t.Fatalf("new dir lacks the protected ACL: %v", err)
	}
	if fixed, err = EnsureProtectedDir(dir); err != nil || fixed {
		t.Fatalf("no drift: fixed=%v err=%v", fixed, err)
	}

	// Children inherit the three ACEs.
	child := filepath.Join(dir, "1.19.0")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	if n := inheritedAces(t, child); n != 3 {
		t.Fatalf("child has %d inherited ACEs, want 3", n)
	}

	everyone, _ := windows.CreateWellKnownSid(windows.WinWorldSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	drifts := map[string]func(){
		"unprotected": func() {
			setSecurity(t, dir, windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil,
				"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")
		},
		"extra ace": func() {
			setSecurity(t, dir, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil,
				"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;FA;;;"+everyone.String()+")")
		},
		"users modify": func() {
			setSecurity(t, dir, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil,
				"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)")
		},
		"owner": func() {
			setSecurity(t, dir, windows.OWNER_SECURITY_INFORMATION, admins, "")
		},
	}
	for name, drift := range drifts {
		t.Run(name, func(t *testing.T) {
			drift()
			if ok, _ := hasProtectedACL(dir); ok {
				t.Fatal("drift not detected")
			}
			if fixed, err := EnsureProtectedDir(dir); err != nil || !fixed {
				t.Fatalf("fix: fixed=%v err=%v", fixed, err)
			}
			if ok, err := hasProtectedACL(dir); !ok || err != nil {
				t.Fatalf("not fixed: %v", err)
			}
			if fixed, err := EnsureProtectedDir(dir); err != nil || fixed {
				t.Fatalf("after fix: fixed=%v err=%v", fixed, err)
			}
		})
	}

	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureProtectedDir(file); err == nil {
		t.Fatal("accepted a file")
	}
}

func setSecurity(t *testing.T, path string, info windows.SECURITY_INFORMATION, owner *windows.SID, sddl string) {
	t.Helper()
	var dacl *windows.ACL
	if sddl != "" {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			t.Fatal(err)
		}
		if dacl, _, err = sd.DACL(); err != nil {
			t.Fatal(err)
		}
	}
	err := withOwnerPrivileges(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
	})
	if err != nil {
		t.Fatalf("set drift: %v", err)
	}
}

func inheritedAces(t *testing.T, path string) int {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			n++
		}
	}
	return n
}
