//go:build windows

package executor

import (
	"testing"

	"golang.org/x/sys/windows"
)

// A detached wsl.exe must get a hidden console: DETACHED_PROCESS makes it
// allocate a visible one, and it also voids CREATE_NO_WINDOW.
func TestDetachAttrsHideConsole(t *testing.T) {
	for i, a := range detachAttrs() {
		if !a.HideWindow {
			t.Errorf("attrs[%d]: HideWindow not set", i)
		}
		if a.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
			t.Errorf("attrs[%d]: CREATE_NO_WINDOW not set (flags %#x)", i, a.CreationFlags)
		}
		if a.CreationFlags&windows.DETACHED_PROCESS != 0 {
			t.Errorf("attrs[%d]: DETACHED_PROCESS set (flags %#x)", i, a.CreationFlags)
		}
	}
}
