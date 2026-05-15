//go:build !windows

package configaudit

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// pipStatOwner returns the file owner via syscall.Stat_t. We bypass the
// Executor here because uid/gid are exposed only through Sys() of an
// os.FileInfo — the mock executor's mockFileInfo can't represent that.
// Tests substitute their own ownerLookup hook so they never reach this.
func pipStatOwner(path string) pipOwnerInfo {
	info, err := os.Stat(path)
	if err != nil {
		return pipOwnerInfo{}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return pipOwnerInfo{}
	}
	oi := pipOwnerInfo{
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
