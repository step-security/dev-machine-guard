package winproc

import "time"

// WaitReleased polls until no process holds any of paths (a file that can
// be opened for exclusive write access, or is missing, is released) or
// timeout passes. It returns the paths still held. A process that has
// exited can keep its image file held while the kernel tears it down, so
// "the process exited" alone is not enough before replacing its files.
func WaitReleased(paths []string, timeout, poll time.Duration) []string {
	deadline := time.Now().Add(timeout)
	for {
		var held []string
		for _, p := range paths {
			if fileHeld(p) {
				held = append(held, p)
			}
		}
		if len(held) == 0 || !time.Now().Before(deadline) {
			return held
		}
		time.Sleep(poll)
	}
}
