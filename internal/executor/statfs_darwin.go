//go:build darwin

package executor

import "syscall"

// Darwin's syscall.Statfs_t has no Frsize field; Bsize is the
// fundamental block size on HFS+/APFS and is what `df` itself uses.
func statfsFragmentSize(s *syscall.Statfs_t) uint64 {
	return uint64(s.Bsize)
}
