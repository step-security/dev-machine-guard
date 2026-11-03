//go:build windows

package device

import "testing"

// stubWindowsFirmware blanks the real host's firmware registry for a test
// that simulates another machine through executor.Mock, so the CIM fixtures
// decide the answer on a Windows runner too.
func stubWindowsFirmware(t *testing.T) {
	t.Helper()
	prev := windowsFirmwareRegistry
	windowsFirmwareRegistry = func() smbiosInfo { return smbiosInfo{} }
	t.Cleanup(func() { windowsFirmwareRegistry = prev })
}
