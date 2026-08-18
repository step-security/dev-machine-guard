//go:build windows

package bgpriority

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

func apply() (string, error) {
	h := windows.CurrentProcess()
	var parts []string

	// Class FIRST: the priority class can't be changed once the process is
	// in background mode, and child processes of a BELOW_NORMAL parent
	// inherit the class (background mode itself is never inherited).
	classErr := windows.SetPriorityClass(h, windows.BELOW_NORMAL_PRIORITY_CLASS)
	if classErr == nil {
		parts = append(parts, "below-normal CPU class (inherited by children)")
	}

	// Background mode lowers this process's IO priority to Very Low (the
	// defrag/indexer tier — deprioritized behind normal IO but continuously
	// serviced) and its memory priority to the lowest band.
	bgErr := windows.SetPriorityClass(h, windows.PROCESS_MODE_BACKGROUND_BEGIN)
	if bgErr == nil {
		parts = append(parts, "background IO/memory mode")
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("SetPriorityClass(BELOW_NORMAL): %v; SetPriorityClass(BACKGROUND_BEGIN): %v", classErr, bgErr)
	}
	return strings.Join(parts, ", "), nil
}
