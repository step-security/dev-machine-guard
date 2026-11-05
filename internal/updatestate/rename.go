package updatestate

import (
	"os"
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
		if err == nil || !isRenameBlocked(err) || !time.Now().Add(wait).Before(deadline) {
			return err
		}
		renameSleep(wait)
		wait = min(2*wait, 5*time.Second)
	}
}

// RenameBlocked reports whether err is a rename RenameDir gave up on
// because an open handle kept blocking it.
func RenameBlocked(err error) bool { return isRenameBlocked(err) }
