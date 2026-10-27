//go:build !windows

package awakeclock

import "time"

var processStart = time.Now()

// Awake is the monotonic clock: it excludes suspend on Linux and macOS.
func (systemClock) Awake() time.Duration { return time.Since(processStart) }
