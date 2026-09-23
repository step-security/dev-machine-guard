package tcc

import (
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// GuardedFiles applies the skipper before direct reads and symlink traversal.
// libraryPaths are fixed, scanner-owned paths relative to ~/Library. They
// retain targeted inventory there without admitting arbitrary Library data.
func GuardedFiles(exec executor.Executor, s *Skipper, maxReadBytes int64, libraryPaths ...string) executor.Executor {
	if exec.GOOS() != "darwin" || s == nil {
		return exec
	}
	var allowed []string
	for _, relative := range libraryPaths {
		allowed = append(allowed, filepath.Join(s.home, "Library", relative))
	}
	guarded := &protectedFiles{}
	guarded.Executor = exec.GuardedFiles([]string{"/"}, func(path string) string {
		// A Library exception must never override the independent volume opt-out.
		if s.withinNetworkVolume(filepath.Clean(path)) {
			guarded.refusals.Add(1)
			return "tcc_protected"
		}
		for _, root := range allowed {
			if strings.HasSuffix(root, "*") {
				prefix := canonicalProtectionPath(strings.TrimSuffix(root, "*"))
				if strings.HasPrefix(canonicalProtectionPath(path), prefix) || hasDirPrefix(prefix, canonicalProtectionPath(path)) {
					return ""
				}
				continue
			}
			if hasDirPrefix(canonicalProtectionPath(path), canonicalProtectionPath(root)) || hasDirPrefix(canonicalProtectionPath(root), canonicalProtectionPath(path)) {
				return ""
			}
		}
		if !s.WithinProtected(path) {
			return ""
		}
		guarded.refusals.Add(1)
		return "tcc_protected"
	}, maxReadBytes)
	return guarded
}

// ProtectedReadsDisabled also gates commands that load configuration themselves;
// the executor's file guard cannot intercept a child process's filesystem reads.
func ProtectedReadsDisabled(exec executor.Executor, s *Skipper) bool {
	return exec.GOOS() == "darwin" && s != nil && (len(s.paths) != 0 || len(s.prefixes) != 0 || len(s.volumes) != 0)
}

// canonicalProtectionPath covers the system Data-volume alias and the standard
// /private aliases without asking the kernel to resolve an untrusted path.
func canonicalProtectionPath(path string) string {
	path = strings.ToLower(filepath.Clean(path))
	if hasDirPrefix(path, "/system/volumes/data") {
		path = strings.TrimPrefix(path, "/system/volumes/data")
	}
	for _, prefix := range []string{"/private/var", "/private/tmp", "/private/etc"} {
		if hasDirPrefix(path, prefix) {
			path = strings.TrimPrefix(path, "/private")
			break
		}
	}
	// Refuse case variants on macOS, including on its default case-insensitive FS.
	return path
}

type protectedFiles struct {
	executor.Executor
	refusals atomic.Uint64
}

// Refusals lets discovery preserve a prior inventory when some roots were refused.
func Refusals(exec executor.Executor) uint64 {
	if guarded, ok := exec.(*protectedFiles); ok {
		return guarded.refusals.Load()
	}
	return 0
}

// HasGuard also gates helper commands that would read outside this reader.
func HasGuard(exec executor.Executor) bool { _, ok := exec.(*protectedFiles); return ok }
