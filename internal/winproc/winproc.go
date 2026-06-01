//go:build !windows

// Package winproc adjusts the OS-process attributes attached to an
// *exec.Cmd. On Windows it suppresses console-window allocation for the
// child; on every other platform it is a no-op so call sites stay
// platform-agnostic.
package winproc

import "os/exec"

// HideWindow is a no-op on non-Windows platforms.
func HideWindow(_ *exec.Cmd) {}

// IsLocalSystem always returns false on non-Windows platforms. The
// SYSTEM-context discrimination only matters for MSI deferred custom
// actions, which are Windows-only.
func IsLocalSystem() bool { return false }
