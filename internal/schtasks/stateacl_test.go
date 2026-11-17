package schtasks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// aclStep stubs one expected icacls invocation.
func aclStep(mock *executor.Mock, path string, args ...string) {
	mock.SetCommand("", "", 0, "icacls", append([]string{path}, args...)...)
}

// stubDir stubs what a directory gets: a reset, the grants, then the owner
// (icacls takes /setowner only on its own).
func stubDir(mock *executor.Mock, path string, usersGrants ...string) {
	aclStep(mock, path, "/reset", "/L", "/Q")
	args := []string{"/inheritance:r", "/grant", "*S-1-5-18:(OI)(CI)F", "/grant", "*S-1-5-32-544:(OI)(CI)F"}
	for _, g := range usersGrants {
		args = append(args, "/grant", "*S-1-5-32-545:"+g)
	}
	aclStep(mock, path, append(args, "/grant", "*S-1-3-0:(OI)(CI)(IO)F", "/L", "/Q")...)
	aclStep(mock, path, "/setowner", "*S-1-5-18", "/L", "/Q")
}

// stubFile stubs what a file gets: a reset, the grants, and the owner for
// the files SYSTEM must own.
func stubFile(mock *executor.Mock, path, usersGrant string, ownedBySystem bool) {
	aclStep(mock, path, "/reset", "/L", "/Q")
	aclStep(mock, path, "/inheritance:r", "/grant", "*S-1-5-18:F", "/grant", "*S-1-5-32-544:F", "/grant", "*S-1-5-32-545:"+usersGrant, "/L", "/Q")
	if ownedBySystem {
		aclStep(mock, path, "/setowner", "*S-1-5-18", "/L", "/Q")
	}
}

var sharedFilesUnderTest = []string{"agent.error.log", "agent.error.log.prev", "agent.log", "agent.log.prev", "seen-users.txt"}

// The state directory gets least-privilege grants: SYSTEM and Administrators
// own it, users list, read and create (and read what SYSTEM adds later,
// through the inherit-only entry), what they create is theirs, the shared
// logs, the visit file and the unscoped run state take Modify, the protected
// files and state\ are read-only for users. Every path is reset before it is
// granted. Only the stubbed invocations are allowed: a blanket Modify grant,
// or any other extra call, would fail the mock.
func TestHardenStateDirACLs_LeastPrivilege(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"config.json", "device-id", "last-run.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "state"), 0o755); err != nil {
		t.Fatal(err)
	}
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(true)
	stubDir(mock, root, "(RX,WD,AD)", "(OI)(IO)R")
	stubDir(mock, filepath.Join(root, "users"), "(RX,WD,AD)", "(OI)(CI)(IO)RX")
	stubDir(mock, filepath.Join(root, "runs"), "(RX,WD)")
	for _, name := range sharedFilesUnderTest {
		stubFile(mock, filepath.Join(root, name), "M", true)
	}
	stubFile(mock, filepath.Join(root, "last-run.json"), "M", false) // unscoped run state: replaceable by the signed-in user
	for _, name := range []string{"config.json", "device-id", "image-builder.json", "multi-user.json"} {
		stubFile(mock, filepath.Join(root, name), "R", true)
	}
	stubDir(mock, filepath.Join(root, "state"), "(OI)(CI)RX")

	if err := hardenStateDirACLs(context.Background(), mock, root); err != nil {
		t.Fatalf("hardenStateDirACLs: %v", err)
	}
	for _, name := range sharedFilesUnderTest {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("shared file %s not created: %v", name, err)
		}
	}
	// The markers users must not be able to plant exist, empty, so the
	// slot is SYSTEM's; an existing file is left alone.
	for _, name := range []string{"image-builder.json", "multi-user.json"} {
		if data, err := os.ReadFile(filepath.Join(root, name)); err != nil || len(data) != 0 {
			t.Errorf("marker %s: data=%q err=%v, want an empty file", name, data, err)
		}
	}
	if data, _ := os.ReadFile(filepath.Join(root, "device-id")); string(data) != "x" {
		t.Errorf("device-id was rewritten: %q", data)
	}
	if _, err := os.Stat(filepath.Join(root, "users")); err != nil {
		t.Errorf("users directory not created: %v", err)
	}
	// Absent files get no grant (nothing stubbed for bootstrap.json or the
	// other run-state files, and the call above succeeded), and a second
	// pass is idempotent.
	if err := hardenStateDirACLs(context.Background(), mock, root); err != nil {
		t.Fatalf("second pass: %v", err)
	}
}

// A link anywhere the grants would touch fails the whole operation before
// any change: a user who could still write the directory could have planted
// it to redirect a SYSTEM grant onto its target.
func TestHardenStateDirACLs_RefusesLinks(t *testing.T) {
	cases := []struct {
		name string
		link string // path under the root replaced by a link
	}{
		{"users directory", "users"},
		{"runs directory", "runs"},
		{"shared log", "agent.error.log"},
		{"protected marker", "image-builder.json"},
		{"state directory", "state"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			target := t.TempDir()
			if err := os.Symlink(target, filepath.Join(root, tc.link)); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("creating a symlink needs a privilege here: %v", err)
				}
				t.Fatal(err)
			}
			mock := executor.NewMock() // nothing stubbed: any icacls call would fail with its own message
			mock.SetGOOS("windows")
			mock.SetIsRoot(true)
			err := hardenStateDirACLs(context.Background(), mock, root)
			if err == nil || !strings.Contains(err.Error(), "it is a link") {
				t.Fatalf("err = %v, want a refusal naming the link", err)
			}
			if entries, _ := os.ReadDir(target); len(entries) != 0 {
				t.Errorf("the link's target was written to: %v", entries)
			}
		})
	}
	t.Run("the root itself", func(t *testing.T) {
		target := t.TempDir()
		root := filepath.Join(t.TempDir(), "StepSecurity")
		if err := os.Symlink(target, root); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("creating a symlink needs a privilege here: %v", err)
			}
			t.Fatal(err)
		}
		mock := executor.NewMock()
		mock.SetGOOS("windows")
		mock.SetIsRoot(true)
		if err := hardenStateDirACLs(context.Background(), mock, root); err == nil || !strings.Contains(err.Error(), "it is a link") {
			t.Fatalf("err = %v, want a refusal naming the link", err)
		}
	})
}

// The first icacls failure is reported with the path, so the install can log
// which grant did not land and go on.
func TestHardenStateDirACLs_ReportsTheFailingGrant(t *testing.T) {
	root := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(true)
	// Nothing stubbed: the very first call, the reset of the root, fails.
	err := hardenStateDirACLs(context.Background(), mock, root)
	if err == nil || !strings.Contains(err.Error(), "icacls "+root) {
		t.Fatalf("expected the root grant failure, got %v", err)
	}
}
