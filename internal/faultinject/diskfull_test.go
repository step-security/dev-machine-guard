//go:build selfupdate_faults

package faultinject

import (
	"errors"
	"runtime"
	"syscall"
	"testing"
)

func TestDiskFullErrno(t *testing.T) {
	t.Setenv("DMG_FAULT", "S4.manifest:diskfull")
	err := Point("S4.manifest")
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		t.Fatalf("diskfull = %v, want a wrapped errno", err)
	}
	want := syscall.ENOSPC
	if runtime.GOOS == "windows" {
		want = syscall.Errno(112) // ERROR_DISK_FULL
	}
	if errno != want {
		t.Fatalf("errno = %d, want %d", errno, want)
	}
}
