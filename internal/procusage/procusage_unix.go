//go:build !windows

package procusage

import "syscall"

// readUsage reads self and child counters via getrusage. Children count
// here because executor.Run waits on every subprocess it starts, and
// getrusage only credits reaped children.
func readUsage() rusage {
	out := rusage{childrenAttributed: true}

	var self syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &self); err == nil {
		out.userMs = timevalMs(self.Utime)
		out.sysMs = timevalMs(self.Stime)
		out.peakRSSBytes = maxRSSToBytes(int64(self.Maxrss))
	}

	var children syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &children); err == nil {
		out.childUserMs = timevalMs(children.Utime)
		out.childSysMs = timevalMs(children.Stime)
		out.maxChildRSSBytes = maxRSSToBytes(int64(children.Maxrss))
	}

	return out
}

// timevalMs converts a Timeval to milliseconds. Usec is int64 on Linux
// and int32 on Darwin, so both fields are widened explicitly.
func timevalMs(tv syscall.Timeval) int64 {
	return int64(tv.Sec)*1000 + int64(tv.Usec)/1000
}
