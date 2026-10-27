//go:build windows

package launcher

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows/registry"
)

// Needs an elevated process (GitHub's windows-latest runners are).
func TestSetRunningVersion_WritesHKLM(t *testing.T) {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, runningVersionKey, registry.ALL_ACCESS|registry.WOW64_64KEY)
	if err != nil {
		t.Skipf("HKLM not writable (not elevated?): %v", err)
	}
	defer k.Close()
	prev, _, perr := k.GetStringValue("RunningVersion")
	t.Cleanup(func() {
		if perr == nil {
			_ = k.SetStringValue("RunningVersion", prev)
		} else if errors.Is(perr, registry.ErrNotExist) {
			_ = k.DeleteValue("RunningVersion")
		}
	})
	if err := SetRunningVersion("9.8.7"); err != nil {
		t.Fatal(err)
	}
	got, _, err := k.GetStringValue("RunningVersion")
	if err != nil || got != "9.8.7" {
		t.Fatalf("RunningVersion = %q, %v", got, err)
	}
}
