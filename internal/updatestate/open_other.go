//go:build !windows

package updatestate

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// openShared opens path read-only without following a final symlink and
// without blocking on a FIFO.
func openShared(path string) (*os.File, error) {
	// #nosec G304 -- callers pass layout-derived paths.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%w: %w", errUnreadable, err)
	}
	return f, err
}
