package tcc

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The network-volume class is driven entirely by the mount list handed to
// build(), so these tests run on every platform — only the enumeration
// itself (networkVolumeMounts) is darwin-specific.

func TestSkipNetworkVolumes(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		override *bool
		want     bool
	}{
		{"nil override → walk (default keeps container coverage)", nil, false},
		{"explicit include (true) → walk", &trueVal, false},
		{"explicit exclude (false) → skip", &falseVal, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SkipNetworkVolumes(tc.override); got != tc.want {
				t.Errorf("SkipNetworkVolumes(%v) = %v, want %v", tc.override, got, tc.want)
			}
		})
	}
}

func TestSkipper_NetworkVolumeMatching(t *testing.T) {
	// The OrbStack mount is the case from issue #177; /Volumes/share stands
	// in for a conventional SMB/NFS mount.
	mounts := []string{"/Users/alice/OrbStack", "/Volumes/share"}
	s := build("/Users/alice", false, mounts)
	if s == nil {
		t.Fatal("build with mounts must not return nil")
	}

	tests := []struct {
		name     string
		path     string
		walkRoot string
		want     bool
	}{
		{"mount point itself skipped", "/Users/alice/OrbStack", "/Users/alice", true},
		{"trailing slash skipped", "/Users/alice/OrbStack/", "/Users/alice", true},
		{"nested under mount skipped", "/Users/alice/OrbStack/docker/containers", "/Users/alice", true},
		{"second mount skipped", "/Volumes/share/code", "/Volumes", true},
		{"sibling of mount not skipped", "/Users/alice/OrbStack-backup", "/Users/alice", false},
		{"dotted sibling of mount not skipped", "/Users/alice/OrbStack.old", "/Users/alice", false},
		{"unrelated path not skipped", "/Users/alice/code", "/Users/alice", false},
		{"explicit walk root opts in", "/Users/alice/OrbStack", "/Users/alice/OrbStack", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := s.ShouldSkip(tc.path, tc.walkRoot); got != tc.want {
				t.Errorf("ShouldSkip(%q, %q) = %v, want %v", tc.path, tc.walkRoot, got, tc.want)
			}
		})
	}

	// WithinProtected must match the same set: detectors that resolve a deep
	// path directly would otherwise stat inside the volume and fire the
	// prompt the skip exists to avoid.
	for _, p := range []string{"/Users/alice/OrbStack", "/Users/alice/OrbStack/docker/containers/x", "/Volumes/share"} {
		if !s.WithinProtected(p) {
			t.Errorf("WithinProtected(%q) = false, want true", p)
		}
	}
	if s.WithinProtected("/Users/alice/code") {
		t.Error("WithinProtected must not match a path outside every mount")
	}
}

// The protected-dirs class is off in this Skipper, so a network-volume-only
// run must not start skipping ~/Documents as a side effect.
func TestSkipper_VolumesOnlyLeavesProtectedDirsAlone(t *testing.T) {
	s := build("/Users/alice", false, []string{"/Users/alice/OrbStack"})
	if s.ShouldSkip("/Users/alice/Documents", "/Users/alice") {
		t.Error("volumes-only Skipper must not skip protected dirs")
	}
	if s.Candidates() != nil {
		t.Error("volumes-only Skipper must report no protected-dir candidates")
	}
}

func TestSkipper_NetworkVolumesAccessor(t *testing.T) {
	mounts := []string{"/Users/alice/OrbStack", "/Volumes/share"}
	s := build("/Users/alice", true, mounts)
	got := s.NetworkVolumes()
	if !reflect.DeepEqual(got, mounts) {
		t.Errorf("NetworkVolumes() = %v, want %v", got, mounts)
	}
	// Callers log this slice; mutating the copy must not corrupt the skipper.
	got[0] = "/mutated"
	if s.volumes[0] != mounts[0] {
		t.Error("NetworkVolumes must return a copy")
	}

	var nilS *Skipper
	if nilS.NetworkVolumes() != nil {
		t.Error("nil Skipper NetworkVolumes should return nil")
	}
	if build("/Users/alice", true, nil).NetworkVolumes() != nil {
		t.Error("Skipper with no mounts should report no network volumes")
	}
}

func TestSkipper_HitsRecordMountNotLeaf(t *testing.T) {
	s := build("", false, []string{"/Users/alice/OrbStack"})
	s.ShouldSkip("/Users/alice/OrbStack/docker/containers", "/Users/alice")
	hits := s.Hits()
	if hits["/Users/alice/OrbStack"] != 1 {
		t.Errorf("hit should be recorded against the mount point, got %v", hits)
	}
}

func TestBuild_NilWhenNothingToSkip(t *testing.T) {
	if s := build("/Users/alice", false, nil); s != nil {
		t.Errorf("build with both classes off must return nil, got %+v", s)
	}
	// Nil is the documented "no skipping" value and every method tolerates it.
	var nilS *Skipper
	if nilS.ShouldSkip("/Users/alice/OrbStack", "/Users/alice") {
		t.Error("nil Skipper must not skip")
	}
}

// TestSkipper_WalkNeverEntersSkippedVolume drives a real filepath.WalkDir the
// way every detector does. What fires the TCC prompt is reading the mount
// point, not seeing it listed in its parent, so the contract that matters is:
// the callback is invoked for the mount dir itself, SkipDir keeps the walk
// out of it, and nothing beneath it is ever visited.
func TestSkipper_WalkNeverEntersSkippedVolume(t *testing.T) {
	home := t.TempDir()
	mount := filepath.Join(home, "OrbStack")
	if err := os.MkdirAll(filepath.Join(mount, "docker", "containers", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "code", "app"), 0o755); err != nil {
		t.Fatal(err)
	}

	s := build(home, false, []string{mount})
	var visited []string
	err := filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && s.ShouldSkip(path, home) {
			return filepath.SkipDir
		}
		visited = append(visited, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range visited {
		if p != mount && hasDirPrefix(p, mount) {
			t.Errorf("walk descended into a skipped network volume: %q", p)
		}
	}
	if !hasVisited(visited, filepath.Join(home, "code", "app")) {
		t.Error("walk must still cover the rest of the tree")
	}
	if s.Hits()[mount] != 1 {
		t.Errorf("expected exactly one recorded hit on the mount, got %v", s.Hits())
	}
}

func hasVisited(visited []string, want string) bool {
	for _, p := range visited {
		if p == want {
			return true
		}
	}
	return false
}

// TestForRun_DefaultsMatchPreToggleBehavior is the no-surprise guarantee for
// already-deployed fleets: with neither toggle set, the Skipper must behave
// exactly as the pre-toggle New(home) did. A regression here means an agent
// upgrade silently changes which paths a scan walks — and on macOS, walking
// something new is how a customer gets a TCC prompt out of nowhere.
func TestForRun_DefaultsMatchPreToggleBehavior(t *testing.T) {
	home := "/Users/alice"
	before, after := New(home), ForRun(home, nil, nil)

	if after == nil {
		t.Fatal("default run must still produce a Skipper")
	}
	if after.NetworkVolumes() != nil {
		t.Error("default run must not skip any network volume")
	}
	if !reflect.DeepEqual(before.Candidates(), after.Candidates()) {
		t.Errorf("protected-dir list drifted: %v vs %v", before.Candidates(), after.Candidates())
	}
	for _, p := range []string{
		home,
		home + "/Documents",
		home + "/Library",
		home + "/code/app",
		home + "/OrbStack",
		home + "/OrbStack/docker/containers",
		"/Volumes/share",
	} {
		if before.ShouldSkip(p, home) != after.ShouldSkip(p, home) {
			t.Errorf("ShouldSkip(%q) drifted from pre-toggle behavior", p)
		}
		if before.WithinProtected(p) != after.WithinProtected(p) {
			t.Errorf("WithinProtected(%q) drifted from pre-toggle behavior", p)
		}
	}

	// The other pre-existing shape: --include-tcc-protected produced a nil
	// skipper, and still must.
	optedIn := true
	if s := ForRun(home, &optedIn, nil); s != nil {
		t.Error("--include-tcc-protected must still yield a nil Skipper by default")
	}
}

func TestForRun_TogglePolarity(t *testing.T) {
	trueVal := true
	falseVal := false

	// Default run: protected dirs skipped (darwin) or nothing to skip
	// (elsewhere), network volumes always walked.
	if s := ForRun("/Users/alice", nil, nil); s.NetworkVolumes() != nil {
		t.Error("default run must walk network volumes")
	}
	// Both classes opted in → nothing to skip at all.
	if s := ForRun("/Users/alice", &trueVal, &trueVal); s != nil {
		t.Error("include-everything run must produce a nil Skipper")
	}
	// Opting out of network volumes must not disturb the protected-dirs
	// class, which stays on its own default.
	optOut := ForRun("/Users/alice", nil, &falseVal)
	if optOut == nil {
		t.Fatal("network-volume opt-out must produce a Skipper")
	}
}
