//go:build windows

package updatestate

import (
	"os"

	"golang.org/x/sys/windows"
)

// openShared opens path for reading with FILE_SHARE_DELETE, so a reader
// never makes a concurrent MoveFileEx replace fail. Reparse points are
// opened as themselves, and directories open too (FILE_FLAG_BACKUP_SEMANTICS),
// so callers reject both as non-regular (corrupt) rather than seeing an
// access-denied I/O error.
func openShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
