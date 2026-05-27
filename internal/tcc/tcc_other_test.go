//go:build !darwin

package tcc

import "testing"

func TestSkipper_NoOpOnNonDarwin(t *testing.T) {
	s := New("/home/alice")
	if s.ShouldSkip("/home/alice/Documents", "/home/alice") {
		t.Error("Skipper should be a no-op on non-darwin")
	}
	if s.Candidates() != nil {
		t.Error("Candidates should be nil on non-darwin")
	}
}
