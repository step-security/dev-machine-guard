//go:build !windows

package selfupdate

import "os"

// swapBinary installs src at dst with one atomic rename. Unlinking a running
// image is legal on Unix: this process keeps executing the now-unlinked
// inode, and the next scheduled fire picks up the new one.
func swapBinary(src, dst string) error {
	return os.Rename(src, dst)
}
