//go:build !darwin && !linux && !windows

package rules

import "os"

// statTimes has no portable source for birth/ctime on other platforms; size
// and mtime (set by the shared fileAttrs) remain available.
func statTimes(_ os.FileInfo) (createdAt, changedAt int64) {
	return 0, 0
}
