package schtasks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// aclStep is one expected icacls invocation.
func aclStep(mock *executor.Mock, path string, args ...string) {
	mock.SetCommand("", "", 0, "icacls", append([]string{path}, args...)...)
}

// The state directory gets least-privilege grants: SYSTEM and Administrators
// own it, users list, read and create, what they create is theirs, the
// shared log and visit files take appends, the protected files and state\
// are read-only for users. Only the stubbed invocations are allowed: a
// blanket Modify grant, or any other extra call, would fail the mock.
func TestHardenStateDirACLs_LeastPrivilege(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"config.json", "device-id"} {
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
	aclStep(mock, root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(RX,WD,AD)", "/grant:r", "*S-1-3-0:(OI)(CI)(IO)F", "/Q")
	aclStep(mock, filepath.Join(root, "users"), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(CI)(RX,WD,AD)", "/grant:r", "*S-1-3-0:(OI)(CI)(IO)F", "/Q")
	for _, name := range []string{"agent.error.log", "seen-users.txt"} {
		aclStep(mock, filepath.Join(root, name), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F", "/grant:r", "*S-1-5-32-545:(RD,WD,AD)", "/Q")
	}
	for _, name := range []string{"config.json", "device-id"} {
		aclStep(mock, filepath.Join(root, name), "/inheritance:r", "/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F", "/grant:r", "*S-1-5-32-545:R", "/Q")
	}
	aclStep(mock, filepath.Join(root, "state"), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(OI)(CI)RX", "/Q")

	if err := hardenStateDirACLs(context.Background(), mock, root); err != nil {
		t.Fatalf("hardenStateDirACLs: %v", err)
	}
	for _, name := range []string{"agent.error.log", "seen-users.txt"} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("shared file %s not created: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "users")); err != nil {
		t.Errorf("users directory not created: %v", err)
	}
	// Absent protected files get no grant (nothing stubbed for them, and the
	// call above succeeded), and a second pass is idempotent.
	if err := hardenStateDirACLs(context.Background(), mock, root); err != nil {
		t.Fatalf("second pass: %v", err)
	}
}

// The first icacls failure is reported with the path, so the install can log
// which grant did not land and go on.
func TestHardenStateDirACLs_ReportsTheFailingGrant(t *testing.T) {
	root := t.TempDir()
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(true)
	// Nothing stubbed: the very first grant, on the root, fails.
	err := hardenStateDirACLs(context.Background(), mock, root)
	if err == nil || !strings.Contains(err.Error(), "icacls "+root) {
		t.Fatalf("expected the root grant failure, got %v", err)
	}
}
