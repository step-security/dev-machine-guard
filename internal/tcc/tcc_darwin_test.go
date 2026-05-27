//go:build darwin

package tcc

import "testing"

func TestSkipper_ShouldSkip(t *testing.T) {
	home := "/Users/alice"
	s := New(home)

	tests := []struct {
		name     string
		path     string
		walkRoot string
		want     bool
	}{
		{"documents skipped", "/Users/alice/Documents", "/Users/alice", true},
		{"documents trailing slash", "/Users/alice/Documents/", "/Users/alice", true},
		{"downloads skipped", "/Users/alice/Downloads", "/Users/alice", true},
		{"desktop skipped", "/Users/alice/Desktop", "/Users/alice", true},
		// ~/Library is matched at the parent — the walker SkipDirs there
		// and never descends into Mail/Photos/Music/Containers/etc., so
		// we no longer need exact-match entries for the gated subdirs.
		// ShouldSkip on a Library subdir on its own returns false because
		// WalkDir wouldn't reach it after the parent skip; the test below
		// pins this behavior so future readers don't get surprised.
		{"library parent skipped", "/Users/alice/Library", "/Users/alice", true},
		{"library subdir not directly matched (walker handles via parent SkipDir)", "/Users/alice/Library/Mail", "/Users/alice", false},
		{"trash skipped", "/Users/alice/.Trash", "/Users/alice", true},
		{"random code dir not skipped", "/Users/alice/code", "/Users/alice", false},
		{"vscode dotdir not skipped", "/Users/alice/.vscode", "/Users/alice", false},
		{"walk root opt-in", "/Users/alice/Documents", "/Users/alice/Documents", false},
		{"walk root opt-in trailing slash", "/Users/alice/Documents", "/Users/alice/Documents/", false},
		{"library walk root opt-in", "/Users/alice/Library", "/Users/alice/Library", false},
		{"timemachine prefix matched", "/Volumes/.timemachine.donottouch/2026-05-25", "/Volumes/MyDrive", true},
		{"timemachine exact prefix", "/Volumes/.timemachine", "/Volumes/MyDrive", true},
		{"timemachine subdir slash", "/Volumes/.timemachine/snap", "/Volumes/MyDrive", true},
		{"timemachine_backup not matched", "/Volumes/.timemachine_backup", "/Volumes/MyDrive", false},
		{"timemachineuser not matched", "/Volumes/.timemachineuser/foo", "/Volumes/MyDrive", false},
		{"other volume not matched", "/Volumes/MyDrive/code", "/Volumes/MyDrive", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := s.ShouldSkip(tc.path, tc.walkRoot)
			if got != tc.want {
				t.Errorf("ShouldSkip(%q, %q) = %v, want %v", tc.path, tc.walkRoot, got, tc.want)
			}
		})
	}
}

func TestSkipper_NilSafe(t *testing.T) {
	var s *Skipper
	if s.ShouldSkip("/Users/alice/Documents", "/Users/alice") {
		t.Error("nil Skipper ShouldSkip should return false")
	}
	if s.Candidates() != nil {
		t.Error("nil Skipper Candidates should return nil")
	}
}

func TestSkipper_EmptyHome(t *testing.T) {
	s := New("")
	if s.ShouldSkip("/Users/alice/Documents", "/Users/alice") {
		t.Error("Skipper with empty home should not match home-anchored paths")
	}
	if !s.ShouldSkip("/Volumes/.timemachine.donottouch/snap", "/Volumes/MyDrive") {
		t.Error("Skipper with empty home should still match absolute-prefix entries")
	}
	if s.Candidates() != nil {
		t.Error("Skipper with empty home should have nil Candidates")
	}
}

func TestEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		override *bool
		want     bool
	}{
		{"nil override → skipper on (default skip)", nil, true},
		{"explicit include (true) → skipper off", &trueVal, false},
		{"explicit exclude (false) → skipper on", &falseVal, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Enabled(tc.override); got != tc.want {
				t.Errorf("Enabled(%v) = %v, want %v", tc.override, got, tc.want)
			}
		})
	}
}

func TestSkipper_CandidatesSorted(t *testing.T) {
	s := New("/Users/alice")
	cands := s.Candidates()
	if len(cands) == 0 {
		t.Fatal("expected non-empty candidates on darwin")
	}
	for i := 1; i < len(cands); i++ {
		if cands[i-1] > cands[i] {
			t.Errorf("candidates not sorted: %q > %q at index %d", cands[i-1], cands[i], i)
		}
	}
}
