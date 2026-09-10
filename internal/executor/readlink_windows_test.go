//go:build windows

package executor

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReal_ReadlinkJunction pins the two facts the skills detector's junction
// handling rests on, against a real junction: os.ReadDir reports it as
// ModeIrregular (not ModeSymlink, IsDir false), and Readlink returns its
// target — in the NT namespace, which the detector strips.
func TestReal_ReadlinkJunction(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range entries {
		if e.Name() != "link" {
			continue
		}
		found = true
		if e.Type()&os.ModeIrregular == 0 || e.Type()&os.ModeSymlink != 0 || e.IsDir() {
			t.Errorf("junction Type() = %v, want ModeIrregular and not ModeSymlink/dir", e.Type())
		}
	}
	if !found {
		t.Fatal("junction entry missing from ReadDir")
	}

	got, err := NewReal().Readlink(link)
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	stripped := strings.TrimPrefix(strings.TrimPrefix(got, `\??\`), `\\?\`)
	if !strings.EqualFold(stripped, target) {
		t.Errorf("Readlink = %q (stripped %q), want %q", got, stripped, target)
	}
}
