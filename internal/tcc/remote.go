package tcc

import (
	"path"
	"sort"
	"strconv"
	"strings"
)

// remoteFSTypes are Linux filesystem types whose walks can block on an
// unreachable server. FUSE is risky in general but only sshfs is
// recognizably remote; autofs mount points trigger on-demand (often NFS)
// mounts on access.
var remoteFSTypes = map[string]bool{
	"nfs": true, "nfs4": true,
	"cifs": true, "smb3": true, "smbfs": true,
	"fuse.sshfs": true,
	"autofs":     true,
}

func isRemoteFSType(fstype string) bool { return remoteFSTypes[fstype] }

// parseRemoteMounts returns the remote mount points listed in a
// /proc/self/mountinfo dump, sorted. "/" is never returned.
func parseRemoteMounts(mountinfo string) []string {
	var mounts []string
	for line := range strings.SplitSeq(mountinfo, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		if !ok {
			continue
		}
		fields, rest := strings.Fields(pre), strings.Fields(post)
		if len(fields) < 5 || len(rest) < 1 || !isRemoteFSType(rest[0]) {
			continue
		}
		mount := path.Clean(unescapeMountinfo(fields[4]))
		if mount == "/" || mount == "." {
			continue
		}
		mounts = append(mounts, mount)
	}
	sort.Strings(mounts)
	return mounts
}

// unescapeMountinfo decodes the kernel's \ooo octal escapes (space, tab,
// newline, backslash) in a mountinfo path field.
func unescapeMountinfo(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Windows file attributes marking cloud-sync placeholders (OneDrive Files
// On-Demand and similar): opening or listing them hydrates from the network.
const (
	fileAttributeRecallOnOpen       = 0x00040000
	fileAttributeRecallOnDataAccess = 0x00400000
	driveRemote                     = 4 // GetDriveType DRIVE_REMOTE
)

func isCloudPlaceholderAttrs(attrs uint32) bool {
	return attrs&(fileAttributeRecallOnOpen|fileAttributeRecallOnDataAccess) != 0
}
