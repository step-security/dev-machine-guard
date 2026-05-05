//go:build !windows

package detector

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// statOwner returns the owning uid/gid of a path. We deliberately bypass the
// Executor interface here because:
//  1. uid/gid is exposed only via syscall.Stat_t on the Sys() of an os.FileInfo
//     and the mock executor's mockFileInfo can't represent that.
//  2. The detector exposes ownerLookup as a hook so tests substitute a stub
//     and never reach this function.
func statOwner(path string) ownerInfo {
	info, err := os.Stat(path)
	if err != nil {
		return ownerInfo{}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ownerInfo{}
	}
	oi := ownerInfo{
		UID: int(st.Uid),
		GID: int(st.Gid),
		OK:  true,
	}
	if u, err := user.LookupId(strconv.Itoa(oi.UID)); err == nil {
		oi.OwnerName = u.Username
	}
	if g, err := user.LookupGroupId(strconv.Itoa(oi.GID)); err == nil {
		oi.GroupName = g.Name
	}
	return oi
}
