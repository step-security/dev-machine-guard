//go:build !windows

package winproc

// StopUnder is Windows-only.
func StopUnder(string) ([]string, error) { return nil, nil }

func fileHeld(string) bool { return false }
