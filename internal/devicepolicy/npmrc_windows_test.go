//go:build windows

package devicepolicy

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/secureuserfile"
	"golang.org/x/sys/windows"
)

func TestNPMRCWriterWindowsAppliesTargetUserSecurity(t *testing.T) {
	homeDir := t.TempDir()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	w, err := NewNPMRCWriter(secureTestExecutor{Executor: executor.NewReal(), user: u})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(homeDir, ".npmrc*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := w.secureHome.VerifyOwner(file, filepath.Base(path)); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		secure, err := w.secureHome.MetadataSecure(file, secureuserfile.FileMode)
		_ = file.Close()
		if err != nil || !secure {
			t.Fatalf("metadata %q = %v, %v", path, secure, err)
		}
	}
}

func TestNPMRCWriterWindowsRejectsWrongOwnerWithoutMutation(t *testing.T) {
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".npmrc")
	before := []byte("registry=https://registry.npmjs.org/\r\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	u.Uid = systemSID.String()
	w, err := NewNPMRCWriter(secureTestExecutor{Executor: executor.NewReal(), user: u})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write(stdBody); !errors.Is(err, secureuserfile.ErrTargetUnusable) {
		t.Fatalf("Write error = %v, want wrong-owner refusal", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("wrong-owner file changed")
	}
}

func TestNPMRCWriterWindowsBackupAndRollback(t *testing.T) {
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".npmrc")
	before := []byte("registry=https://registry.npmjs.org/\r\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	w, err := NewNPMRCWriter(secureTestExecutor{Executor: executor.NewReal(), user: u})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write(stdSettingsBody); err != nil {
		t.Fatal(err)
	}
	backups, err := filepath.Glob(path + ".dmg-*.bak")
	if err != nil || len(backups) == 0 {
		t.Fatalf("backups = %v, %v, want at least one", backups, err)
	}
	if err := w.RestoreSnapshot(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("rollback content = %q, %v, want %q", after, err, before)
	}
}

func TestNPMRCWriterWindowsClearRestoresGeneratedLifecycle(t *testing.T) {
	tests := []struct {
		name        string
		initial     []byte
		body        string
		wantAbsent  bool
		wantContent []byte
	}{
		{name: "agent-created file returns to absent", wantAbsent: true},
		{name: "pre-existing empty file remains empty", initial: []byte{}, wantContent: []byte{}},
		{name: "pre-existing CRLF config restores exactly", initial: []byte("registry=https://registry.npmjs.org/\r\n"), wantContent: []byte("registry=https://registry.npmjs.org/\r\n")},
		{name: "pre-existing settings conflict restores exactly", initial: []byte("save-exact=false\r\n"), body: stdSettingsBody, wantContent: []byte("save-exact=false\r\n")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			homeDir := t.TempDir()
			path := filepath.Join(homeDir, ".npmrc")
			if tc.initial != nil {
				if err := os.WriteFile(path, tc.initial, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			u, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			u.HomeDir = homeDir
			normalizeSecureTestUser(t, u)
			w, err := NewNPMRCWriter(secureTestExecutor{Executor: executor.NewReal(), user: u})
			if err != nil {
				t.Fatal(err)
			}
			defer w.Close()
			body := tc.body
			if body == "" {
				body = stdBody
			}
			if _, err := w.Write(body); err != nil {
				t.Fatal(err)
			}
			state := AppliedTargetState{}
			if err := w.CompleteState(AppliedTargetState{}, false, &state); err != nil {
				t.Fatal(err)
			}
			if err := w.PrepareClear(state, true); err != nil {
				t.Fatal(err)
			}
			if changed, err := w.Clear(); err != nil || !changed {
				t.Fatalf("Clear = %v, %v, want changed", changed, err)
			}
			got, err := os.ReadFile(path)
			if tc.wantAbsent {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("created .npmrc still exists: %v", err)
				}
			} else if err != nil || !bytes.Equal(got, tc.wantContent) {
				t.Fatalf("restored content = %q, %v, want %q", got, err, tc.wantContent)
			}
			if residue, err := filepath.Glob(path + ".dmg-*.bak"); err != nil || len(residue) != 0 {
				t.Fatalf("backup residue = %v, %v", residue, err)
			}
		})
	}
}

func TestNPMRCWriterWindowsRepairsWeakExpectedPrincipalACL(t *testing.T) {
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".npmrc")
	if err := os.WriteFile(path, []byte("registry=https://registry.npmjs.org/\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	targetSID, err := windows.StringToSid(u.Uid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		npmTestExplicitAccess(targetSID, windows.GENERIC_READ, windows.TRUSTEE_IS_USER),
		npmTestExplicitAccess(systemSID, windows.GENERIC_READ, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	w, err := NewNPMRCWriter(secureTestExecutor{Executor: executor.NewReal(), user: u})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Write(stdBody); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	secure, err := w.secureHome.MetadataSecure(file, secureuserfile.FileMode)
	_ = file.Close()
	if err != nil || !secure {
		t.Fatalf("repaired metadata = %v, %v, want secure", secure, err)
	}
}

func TestNPMRCWriterWindowsObservesSettingsWithWeakMDMACL(t *testing.T) {
	homeDir := t.TempDir()
	path := filepath.Join(homeDir, ".npmrc")
	if err := os.WriteFile(path, []byte(boundedMDMBlock(stdSettingsBody)), 0o600); err != nil {
		t.Fatal(err)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	u.HomeDir = homeDir
	normalizeSecureTestUser(t, u)
	targetSID, err := windows.StringToSid(u.Uid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		npmTestExplicitAccess(targetSID, windows.GENERIC_READ, windows.TRUSTEE_IS_USER),
		npmTestExplicitAccess(systemSID, windows.GENERIC_READ, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	w, err := NewNPMRCWriter(secureTestExecutor{Executor: executor.NewReal(), user: u})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	present, observed, err := w.ProbeContentNPM(stdSettingsBody)
	if err != nil {
		t.Fatalf("ProbeContentNPM: %v", err)
	}
	if !present {
		t.Fatal("weak-ACL settings MDM block was not observed")
	}
	if len(observed) != 4 {
		t.Fatalf("weak-ACL settings observed keys = %d, want 4", len(observed))
	}
}

func npmTestExplicitAccess(sid *windows.SID, permissions windows.ACCESS_MASK, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: permissions,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
