//go:build linux

package tcc

import "os"

// Off macOS there is no prompt to trade against, only the risk of blocking
// on a dead server, so remote mounts are skipped unless explicitly included.
const skipRemoteByDefault = true

// networkVolumeMounts lists remote mounts from the kernel mount table. Reading
// mountinfo never touches the mounts, so a hung server can't block it.
func networkVolumeMounts() []string {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	return parseRemoteMounts(string(data))
}

func cloudPlaceholder(string) bool { return false }
