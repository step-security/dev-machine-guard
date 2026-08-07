//go:build windows

package safepath

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// openVerified opens an already-resolved path and then proves, from the handle
// itself, that the file it landed on is the one that was resolved.
//
// Windows has no openat, so the per-component descriptor chain used on unix is not
// available. Two things stand in for it. FILE_FLAG_OPEN_REPARSE_POINT stops the
// final component being followed, so a leaf replaced by a junction or symlink opens
// the link rather than its target. And GetFinalPathNameByHandle reports the path the
// kernel actually reached after resolving every reparse point above the leaf, so
// comparing it against the resolved path detects an ancestor that changed between
// resolution and open. The verification runs against the same handle the content is
// read from, leaving no second window to swap into. There is no consent layer here,
// so a mismatch prevents reading the wrong file rather than a blocked traversal.
func openVerified(resolved string, wantDir bool) (*os.File, os.FileInfo, error) {
	if _, comps := split(resolved); len(comps) == 0 {
		return nil, nil, refuse(ReasonUnresolved)
	}

	name, err := windows.UTF16PtrFromString(resolved)
	if err != nil {
		return nil, nil, refuse(ReasonUnresolved)
	}
	// BACKUP_SEMANTICS is what allows a directory handle at all; it is required
	// for the directory listing and harmless for a file.
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS | windows.FILE_FLAG_OPEN_REPARSE_POINT)
	h, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return nil, nil, openErr(err)
	}

	final, err := finalPath(h)
	if err != nil || !samePath(final, resolved) {
		_ = windows.CloseHandle(h)
		return nil, nil, refuse(ReasonUnresolved)
	}

	f := os.NewFile(uintptr(h), resolved)
	info, serr := f.Stat()
	if serr != nil {
		_ = f.Close()
		return nil, nil, refuse(ReasonDenied)
	}
	if wantDir && !info.IsDir() {
		// A directory listing of something that is not a directory is a
		// wrong-shaped location, not a readable one.
		_ = f.Close()
		return nil, nil, refuse(ReasonUnresolved)
	}
	return f, info, nil
}

// GetFinalPathNameByHandle flags. Both are zero — the normalized form and a
// drive-letter volume name are the API's defaults — and neither is declared in
// x/sys/windows, so they are named here rather than passing a bare 0.
const (
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0
)

// finalPath returns the canonical DOS path the handle refers to, with the
// extended-length prefix removed so it is comparable to an ordinary path.
func finalPath(h windows.Handle) (string, error) {
	// One page of UTF-16 covers any real path; the retry below handles the rest
	// rather than allocating MAX_LONG_PATH on every read. The size is a constant
	// so the API's word count is spelled without a conversion that could wrap.
	const words = 1024
	buf := make([]uint16, words)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], words, fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", err
	}
	if int(n) > len(buf) {
		if n > windows.MAX_LONG_PATH {
			return "", windows.ERROR_INVALID_PARAMETER
		}
		buf = make([]uint16, n)
		if _, err = windows.GetFinalPathNameByHandle(h, &buf[0], n, fileNameNormalized|volumeNameDOS); err != nil {
			return "", err
		}
	}
	p := windows.UTF16ToString(buf)
	p = strings.TrimPrefix(p, `\\?\`)
	return p, nil
}

// samePath compares the kernel's path for the handle with the path that was
// resolved, ignoring case: the kernel returns the on-disk casing while the resolved
// path carries whatever the catalog and directory entries produced, so a
// case-sensitive comparison would fail on ordinary machines. The cost is that two
// names differing only in case are treated as one.
func samePath(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, `\`), strings.TrimSuffix(b, `\`))
}

// openErr maps a CreateFile failure to a refusal.
func openErr(err error) error {
	switch err {
	case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND:
		return os.ErrNotExist
	case windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION:
		return refuse(ReasonDenied)
	case windows.ERROR_CANT_ACCESS_FILE, windows.ERROR_INVALID_REPARSE_DATA:
		return refuse(ReasonUnresolved)
	default:
		return refuse(ReasonDenied)
	}
}
