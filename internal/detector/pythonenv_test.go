package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// TestExistingDirs verifies existence filtering, symlink resolution + dedupe,
// and subsumed-root dropping (a nested site-packages under a broader install
// tree is not returned as a separate root).
func TestExistingDirs(t *testing.T) {
	root := t.TempDir()
	tree := filepath.Join(root, "py", "3.11")
	sp := filepath.Join(tree, "lib", "python3.11", "site-packages") // nested under tree
	other := filepath.Join(root, "other")
	for _, d := range []string{sp, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// "Current" symlink -> the concrete version tree; must dedupe onto it.
	if err := os.Symlink(tree, filepath.Join(root, "py", "Current")); err != nil {
		t.Fatal(err)
	}

	got := existingDirs(executor.NewReal(), []string{
		tree,
		sp,                                   // subsumed by tree
		filepath.Join(root, "py", "Current"), // symlink -> tree
		other,
		filepath.Join(root, "missing"), // absent
	})

	want := map[string]bool{}
	for _, p := range []string{tree, other} {
		r, err := filepath.EvalSymlinks(p)
		if err != nil {
			t.Fatal(err)
		}
		want[r] = true
	}

	if len(got) != len(want) {
		t.Fatalf("got %d %v, want %d", len(got), got, len(want))
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected root: %s", g)
		}
	}
}

func TestDropSubsumedRoots(t *testing.T) {
	sep := string(filepath.Separator)
	in := []string{
		sep + "a" + sep + "b",
		sep + "a",
		sep + "a" + sep + "b" + sep + "c",
		sep + "x",
		sep + "ab", // NOT under /a — the prefix guard must not drop it
	}
	got := dropSubsumedRoots(in)
	want := []string{sep + "a", sep + "ab", sep + "x"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("missing expected root %s (got %v)", w, got)
		}
	}
}
