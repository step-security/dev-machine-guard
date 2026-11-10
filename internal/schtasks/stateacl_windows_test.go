//go:build windows

package schtasks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// The grants are applied for real to a scratch directory that carries the
// blanket Users:Modify of an earlier install, and what Windows keeps is read
// back: no Modify for Users on the root, the shared log writable, the config
// read-only, a file created in the root afterwards readable through
// inheritance, and the protected files owned by SYSTEM. The owner change
// needs an elevated token; skipped without one.
func TestHardenStateDirACLs_NativeMigration(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token for the owner change")
	}
	root := t.TempDir()
	exec := executor.NewReal()
	ctx := context.Background()
	run := func(name string, args ...string) string {
		t.Helper()
		stdout, stderr, code, err := exec.Run(ctx, name, args...)
		if err != nil || code != 0 {
			t.Fatalf("%s %v: exit %d err %v: %s", name, args, code, err, stderr)
		}
		return stdout
	}
	run("icacls", root, "/grant", "*S-1-5-32-545:(OI)(CI)M", "/Q") // the legacy install's grant
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "agent.log"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := hardenStateDirACLs(ctx, exec, root); err != nil {
		t.Fatalf("hardenStateDirACLs: %v", err)
	}

	rootACL := run("icacls", root)
	if strings.Contains(rootACL, "Users:(OI)(CI)(M)") || strings.Contains(rootACL, "Users:(I)") {
		t.Errorf("a legacy or inherited Users grant survived on the root:\n%s", rootACL)
	}
	for _, want := range []string{"Users:(RX,WD,AD)", "Users:(OI)(IO)(R)"} {
		if !strings.Contains(rootACL, want) {
			t.Errorf("root lacks %s:\n%s", want, rootACL)
		}
	}
	logACL := run("icacls", filepath.Join(root, "agent.log"))
	if !strings.Contains(logACL, "Users:(M)") || strings.Count(logACL, ":(") != 3 {
		t.Errorf("agent.log should grant exactly SYSTEM, Administrators and Users (Modify):\n%s", logACL)
	}
	cfgACL := run("icacls", filepath.Join(root, "config.json"))
	if !strings.Contains(cfgACL, "Users:(R)") || strings.Contains(cfgACL, "Users:(M)") {
		t.Errorf("config.json should be read-only for users:\n%s", cfgACL)
	}
	later := filepath.Join(root, "later.json")
	if err := os.WriteFile(later, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if laterACL := run("icacls", later); !strings.Contains(laterACL, "Users:(I)(R)") {
		t.Errorf("a file created after the grants should inherit read for users:\n%s", laterACL)
	}
	for _, name := range []string{"config.json", "agent.log", "image-builder.json"} {
		if owner := fileOwnerSID(t, filepath.Join(root, name)); owner != "S-1-5-18" {
			t.Errorf("%s owner = %s, want SYSTEM (S-1-5-18)", name, owner)
		}
	}
}

// fileOwnerSID reads a file's owner in process (the runner's PowerShell
// cannot load Get-Acl's module under the test).
func fileOwnerSID(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("reading the owner of %s: %v", path, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatalf("owner of %s: %v", path, err)
	}
	return owner.String()
}
