package updatestate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// renameRetryBudget bounds how long RenameDir keeps retrying a blocked
// rename. Defender's cloud block holds a new executable for up to ~60 s.
var renameRetryBudget = 60 * time.Second

// Seams for tests.
var (
	osRename        = os.Rename
	isRenameBlocked = renameBlocked
	renameSleep     = time.Sleep
	blockedBy       = fileHolders
)

// RenameDir renames a directory, retrying while another process's open
// handle blocks it: on Windows an AV/EDR scanning a freshly written
// executable holds it without FILE_SHARE_DELETE, and the rename of its
// directory fails with ERROR_ACCESS_DENIED until the scan ends. Other
// errors are returned at once.
func RenameDir(src, dst string) error {
	deadline := time.Now().Add(renameRetryBudget)
	wait := 250 * time.Millisecond
	for {
		err := osRename(src, dst)
		if err == nil || !isRenameBlocked(err) {
			return err
		}
		if !time.Now().Add(wait).Before(deadline) {
			return withHolders(err, src)
		}
		renameSleep(wait)
		wait = min(2*wait, 5*time.Second)
	}
}

// RenameBlocked reports whether err is a rename RenameDir gave up on
// because an open handle kept blocking it.
func RenameBlocked(err error) bool { return isRenameBlocked(err) }

// withHolders names the processes holding src's files open (Windows Restart
// Manager), so a blocked rename tells support which AV/EDR to exclude.
func withHolders(err error, src string) error {
	var paths []string
	_ = filepath.WalkDir(src, func(p string, d os.DirEntry, werr error) error {
		if werr == nil && !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	})
	if h := blockedBy(paths); len(h) > 0 {
		return fmt.Errorf("%w (held by %s)", err, strings.Join(h, ", "))
	}
	return fmt.Errorf("%w (holder not identified)", err)
}
