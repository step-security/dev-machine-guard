//go:build darwin

package tcc

import (
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// protectedSuffixes are paths relative to the user's home directory that
// macOS gates behind TCC permission prompts. Categories:
//   - Files & Folders (Catalina+): Desktop, Documents, Downloads
//   - Removable / Network (Catalina+): handled via opt-in search dirs
//   - Photos / Music / Movies (Sequoia hardened): Pictures, Movies, Music
//   - Everything under ~/Library: Mail, Messages, Safari, Mobile Documents,
//     CloudStorage, Containers, plus the long tail of Apple-private
//     subtrees that gain new TCC services with each macOS release.
//
// ~/Library is skipped wholesale rather than per-subpath. Every macOS
// release adds new Apple-managed subtrees behind new TCC services
// (Sonoma's App Management, Sequoia's hardened Pictures/Music/Movies,
// Tahoe's expanded Media Library scope into
// ~/Library/Application Support/com.apple.avfoundation/, and so on),
// so a curated allowlist of "Library/X" entries goes stale on every
// upgrade — at which point a previously-silent walk into one of those
// subtrees starts firing a prompt at end users. ~/Library is the wrong
// place for developer projects / lockfiles / npmrc files anyway; the
// detectors that DO need to read specific paths under ~/Library
// (JetBrains plugins, Claude desktop MCP config, pip global config)
// use targeted ReadDir/ReadFile calls that don't consult this skipper,
// so they're unaffected.
var protectedSuffixes = []string{
	"Desktop",
	"Documents",
	"Downloads",
	"Pictures",
	"Movies",
	"Music",
	"Public",
	".Trash",
	"Library",
}

// protectedAbsolutePrefixes are matched with strings.HasPrefix. Time
// Machine local-snapshot mounts use names like
// /Volumes/.timemachine.donottouch.<uuid> which vary by macOS version, so
// a prefix is more robust than an exact path.
var protectedAbsolutePrefixes = []string{
	"/Volumes/.timemachine",
}

func buildProtectedPaths(home string) map[string]struct{} {
	if home == "" {
		return nil
	}
	cleanedHome := filepath.Clean(home)
	paths := make(map[string]struct{}, len(protectedSuffixes))
	for _, suffix := range protectedSuffixes {
		paths[filepath.Join(cleanedHome, suffix)] = struct{}{}
	}
	return paths
}

func protectedPrefixes() []string {
	return protectedAbsolutePrefixes
}

// mountSlack is extra room in the getfsstat buffer so a volume mounted
// between the count call and the fill call still lands in the result
// rather than silently truncating the list — a missed mount here means a
// prompt for a fleet that asked not to get one.
const mountSlack = 8

// networkVolumeMounts returns the mount points macOS does NOT consider
// local, sorted lexicographically. That set is what TCC gates behind
// kTCCServiceSystemPolicyNetworkVolumes: SMB/NFS/AFP shares, but also the
// virtiofs and NFS mounts container runtimes expose the guest filesystem
// through (OrbStack's ~/OrbStack, Docker Desktop and Colima shares). The
// first walk into one of those fires the "would like to access files on a
// network volume" prompt.
//
// getfsstat reads the kernel's mount table — it does not touch the volumes
// themselves — so building this list is prompt-free even for the mounts it
// is about to exclude. MNT_NOWAIT keeps it that way: it returns cached
// statistics instead of asking each filesystem to refresh, which for a
// stale network mount is also the difference between returning promptly and
// blocking on an unreachable server.
//
// "/" is excluded defensively; the root volume is always local, and a
// misread flag there would skip the entire scan.
func networkVolumeMounts() []string {
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]unix.Statfs_t, n+mountSlack)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil
	}
	if n > len(buf) {
		n = len(buf)
	}

	var mounts []string
	for i := range buf[:n] {
		if buf[i].Flags&unix.MNT_LOCAL != 0 {
			continue
		}
		mount := filepath.Clean(cString(buf[i].Mntonname[:]))
		if mount == "" || mount == "." || mount == "/" {
			continue
		}
		mounts = append(mounts, mount)
	}
	sort.Strings(mounts)
	return mounts
}

// cString converts a NUL-terminated fixed-size C char array to a Go string.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
