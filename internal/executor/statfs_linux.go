//go:build linux

package executor

import "syscall"

func statfsFragmentSize(s *syscall.Statfs_t) uint64 {
	if s.Frsize > 0 {
		return uint64(s.Frsize)
	}
	return uint64(s.Bsize)
}
