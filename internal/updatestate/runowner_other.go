//go:build !windows

package updatestate

import (
	"os"
	"strconv"
)

// RunOwner names this process's user for its run file: the uid.
func RunOwner() string { return strconv.Itoa(os.Getuid()) }
