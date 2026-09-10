package safepath

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReaderReadFileBounds(t *testing.T) {
	root := tempHome(t)
	file := filepath.Join(root, "file")
	writeFile(t, file, "data")
	r := NewReader([]string{root}, nil)
	for _, limit := range []int64{-1, 0, 3, 4, 5} {
		data, err := r.ReadFile(file, limit)
		if limit >= 4 {
			if err != nil || string(data) != "data" {
				t.Errorf("limit %d: read = %q, %v", limit, data, err)
			}
		} else if err == nil || len(data) != 0 {
			t.Errorf("limit %d: expected refusal without contents, got %q, %v", limit, data, err)
		}
	}
	if data, err := r.ReadFile(root, 4); err == nil || len(data) != 0 {
		t.Errorf("directory read = %q, %v; want refusal", data, err)
	}
	if _, err := NewReader(nil, nil).Resolve(file); ReasonOf(err) != ReasonOutsideRoots {
		t.Errorf("empty roots: %v; want outside-roots refusal", err)
	}
}

func TestReaderRoots(t *testing.T) {
	base := tempHome(t)
	home, project, outside := filepath.Join(base, "home"), filepath.Join(base, "project"), filepath.Join(base, "outside")
	for _, root := range []string{home, project, outside} {
		writeFile(t, filepath.Join(root, "skill"), "skill")
	}
	symlink(t, filepath.Join(project, "skill"), filepath.Join(home, "allowed"))
	symlink(t, filepath.Join("..", "project", "skill"), filepath.Join(home, "relative"))
	symlink(t, filepath.Join(outside, "skill"), filepath.Join(home, "refused"))
	roots := []string{home, project}
	r := NewReader(roots, nil)
	roots[1] = outside // caller mutation must not broaden the resolver.
	if got, err := r.Resolve(filepath.Join(home, "allowed")); err != nil || got != filepath.Join(project, "skill") {
		t.Fatalf("explicit-root link = %q, %v", got, err)
	}
	if got, err := r.Resolve(filepath.Join(home, "relative")); err != nil || got != filepath.Join(project, "skill") {
		t.Fatalf("relative explicit-root link = %q, %v", got, err)
	}
	if _, err := r.Resolve(filepath.Join(home, "refused")); ReasonOf(err) != ReasonOutsideRoots {
		t.Fatalf("undeclared target error = %v, want outside-roots refusal", err)
	}
	if _, err := New(home, nil).Resolve(filepath.Join(home, "allowed")); ReasonOf(err) != ReasonOutsideRoots {
		t.Fatalf("single-home resolver error = %v, want outside-roots refusal", err)
	}
}

func TestReaderDotDotAfterSymlinkPreservesTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix symlink traversal semantics")
	}
	home := tempHome(t)
	writeFile(t, filepath.Join(home, "actual", "skill"), "actual")
	writeFile(t, filepath.Join(home, "skill"), "lexical-decoy")
	if err := os.Mkdir(filepath.Join(home, "actual", "inner"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink(t, filepath.Join(home, "actual", "inner"), filepath.Join(home, "alias"))
	raw := home + "/alias/../skill"
	want, err := filepath.EvalSymlinks(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewReader([]string{home}, nil).Resolve(raw)
	if err != nil || got != want {
		t.Fatalf("Resolve(%q) = %q, %v; want real target %q", raw, got, err, want)
	}
	symlink(t, "alias/../skill", filepath.Join(home, "relative"))
	if got, err := NewReader([]string{home}, nil).Resolve(filepath.Join(home, "relative")); err != nil || got != want {
		t.Fatalf("relative target = %q, %v; want %q", got, err, want)
	}
	for _, suffix := range []string{"/../skill", "/."} {
		if _, err := NewReader([]string{home}, nil).Resolve(filepath.Join(home, "skill") + suffix); err == nil {
			t.Errorf("file followed by %q must reject non-directory traversal", suffix)
		}
	}
}
