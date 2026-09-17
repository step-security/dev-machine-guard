//go:build windows

package selfupdate

import (
	"fmt"
	"os"
)

// oldSuffix marks a binary that was renamed aside to free its path. Windows
// refuses to overwrite or unlink a mapped executable image, but it does allow
// renaming one — so replacing a live .exe means moving the running image out
// of the way and dropping the new one into the vacated path. The leftover is
// swept on a later run, once nothing maps it any more.
const oldSuffix = ".old"

// swapBinary installs src at dst, which may be a running executable.
//
// The two renames are not one atomic step: a crash in between leaves dst
// absent, which would strand a binary-periodic install with nothing for the
// scheduler to launch. So a failed install puts the original straight back.
func swapBinary(src, dst string) error {
	aside := dst + oldSuffix
	// A leftover from an earlier update is unmapped by now; if it isn't, the
	// rename below fails and the whole update is retried next tick.
	_ = os.Remove(aside)

	if _, err := os.Stat(dst); err == nil {
		if err := os.Rename(dst, aside); err != nil {
			return fmt.Errorf("move the running image aside: %w", err)
		}
	}

	if err := os.Rename(src, dst); err != nil {
		if rerr := os.Rename(aside, dst); rerr != nil {
			return fmt.Errorf("install failed (%v) and restoring the previous binary failed too: %w", err, rerr)
		}
		return fmt.Errorf("install: %w", err)
	}
	return nil
}

// sweepLeftovers deletes the images earlier updates renamed aside. Runs
// before an update, not after one: the image swapped out by THIS process is
// still mapped by it (and by a parent launcher), so it can only be removed
// once a later run no longer maps it. Best-effort throughout — a leftover
// .old costs one binary's worth of disk and is retried every tick.
func sweepLeftovers(paths ...string) {
	for _, p := range paths {
		_ = os.Remove(p + oldSuffix)
	}
}
