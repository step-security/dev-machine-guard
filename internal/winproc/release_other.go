//go:build !windows

package winproc

// StopUnder is Windows-only.
func StopUnder(string) ([]string, error) { return nil, nil }

// StopUnderExcept is Windows-only.
func StopUnderExcept(string, []string) ([]string, error) { return nil, nil }

// ImageRunning is Windows-only; it reports false.
func ImageRunning(string) bool { return false }

func fileHeld(string) bool { return false }
