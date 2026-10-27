//go:build !windows

package updatestate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// DataRoot is the MSI data root; there is none off Windows.
func DataRoot() string { return "" }

// checkRootProtected requires root and every ancestor to be owned by root
// (uid 0) and not group- or world-writable.
func checkRootProtected(root string) error {
	for p := filepath.Clean(root); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return fmt.Errorf("%s is not owned by root", p)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s is writable by non-root users", p)
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}
