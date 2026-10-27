//go:build selfupdate_faults && !windows

package faultinject

import (
	"os"
	"syscall"
)

var errDiskFull error = syscall.ENOSPC

func runningAsSystem() bool { return os.Geteuid() == 0 }
