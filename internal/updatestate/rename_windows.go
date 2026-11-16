//go:build windows

package updatestate

import (
	"errors"

	"golang.org/x/sys/windows"
)

// renameBlocked reports errors an open handle inside the directory causes.
func renameBlocked(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
