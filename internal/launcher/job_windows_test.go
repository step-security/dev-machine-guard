//go:build windows

package launcher

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestNewKillOnCloseJob_AllowsBreakaway(t *testing.T) {
	job, err := NewKillOnCloseJob()
	if err != nil {
		t.Fatalf("NewKillOnCloseJob: %v", err)
	}
	defer func() { _ = windows.CloseHandle(job) }()

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := windows.QueryInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
		t.Fatalf("QueryInformationJobObject: %v", err)
	}
	want := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK)
	if got := info.BasicLimitInformation.LimitFlags; got&want != want {
		t.Errorf("LimitFlags = %#x, want %#x set", got, want)
	}
}
