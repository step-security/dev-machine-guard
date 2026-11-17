//go:build windows

package schtasks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"golang.org/x/sys/windows"
)

func TestPrepareLogDirectory_NativeACL(t *testing.T) {
	exec := executor.NewReal()
	if !exec.IsRoot() {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			t.Fatal("Windows CI must run the native ACL regression with an elevated token")
		}
		t.Skip("requires an elevated Windows token")
	}
	for _, legacy := range []bool{false, true} {
		name := "fresh"
		if legacy {
			name = "legacy-modify"
		}
		t.Run(name, func(t *testing.T) {
			dir := plainACLTestDir(t)
			users := "0x1200a9"
			if legacy {
				users = "0x1301bf"
			}
			setLogTestDACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;"+users+";;;BU)")
			config := filepath.Join(dir, "config.json")
			if err := os.WriteFile(config, []byte("protected-config"), 0600); err != nil {
				t.Fatal(err)
			}
			setLogTestDACL(t, config, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)")
			before := logTestSDDL(t, config)
			oldLog := filepath.Join(dir, "agent.error.log")
			if err := os.WriteFile(oldLog, []byte("old-log"), 0600); err != nil {
				t.Fatal(err)
			}
			if legacy && logTestUsersRights(t, dir, false)&windows.DELETE == 0 {
				t.Fatal("legacy fixture must reproduce directory DELETE access")
			}
			for attempt := 0; attempt < 2; attempt++ {
				if err := prepareLogDirectory(context.Background(), exec, dir); err != nil {
					t.Fatal(err)
				}
				rights := logTestUsersRights(t, dir, false)
				if rights != 0x1200af {
					t.Fatalf("effective root Users mask=%#x, want read/execute and child creation only", rights)
				}
				if inherited := logTestUsersRights(t, dir, true); inherited&0x1301bf != 0x1301bf {
					t.Fatalf("child-only Users mask=%#x, want Modify", inherited)
				}
				if got := logTestSDDL(t, config); got != before {
					t.Fatalf("protected config ACL changed: %s -> %s", before, got)
				}
				if content, err := os.ReadFile(config); err != nil || string(content) != "protected-config" {
					t.Fatalf("config changed: %q, %v", content, err)
				}
				newState := filepath.Join(dir, "seen-users.txt")
				if err := os.WriteFile(newState, []byte("state"), 0600); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{oldLog, newState} {
					if rights := logTestUsersRights(t, path, false); rights&0x1301bf != 0x1301bf {
						t.Fatalf("Users cannot modify/rotate child %s: mask=%#x", path, rights)
					}
				}
			}
		})
	}
}

func setLogTestDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
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

func logTestSDDL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	return sd.String()
}

func logTestUsersRights(t *testing.T, path string, inheritOnly bool) uint32 {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("missing DACL: %v", err)
	}
	var rights uint32
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE && (ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0) == inheritOnly {
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.IsWellKnown(windows.WinBuiltinUsersSid) {
				rights |= uint32(ace.Mask)
			}
		}
	}
	return rights
}
