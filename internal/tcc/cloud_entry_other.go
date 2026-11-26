//go:build !windows

package tcc

import "os"

// Non-Windows scans have no cloud roots. A configured skipper in portable
// filesystem tests can still exercise the link-resolution rules.
func cloudEntry(path string) (placeholder, link bool, err error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, false, err
	}
	return false, info.Mode()&os.ModeSymlink != 0, nil
}
