package winproc

import (
	"os/exec"
	"testing"
)

// HideWindow must be safe to call from cross-platform code without
// nil-checking — call-site noise is the main reason the helper exists.
func TestHideWindow_NilSafe(t *testing.T) {
	HideWindow(nil)
}

// On every platform a zero-value *exec.Cmd should survive HideWindow
// unchanged in shape (no panics). Field-level assertions live in the
// Windows-only test; this guards the non-Windows stub path too.
func TestHideWindow_ZeroValueCmd(t *testing.T) {
	cmd := exec.Command("true")
	HideWindow(cmd)
	if cmd.Path == "" {
		t.Fatal("HideWindow corrupted cmd.Path")
	}
}
