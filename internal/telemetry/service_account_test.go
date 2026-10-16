package telemetry

import (
	"testing"

	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// TestNoUserLoggedIn_WindowsServiceAccount pins the predicate telemetry uses
// for no_user_logged_in to the shared device.IsServiceAccount, so a scan fired
// under SYSTEM never overwrites the device's developer in the dashboard.
func TestNoUserLoggedIn_WindowsServiceAccount(t *testing.T) {
	m := executor.NewMock()
	m.SetGOOS("windows")
	for user, want := range map[string]bool{
		`NT AUTHORITY\SYSTEM`:        true,
		`NT AUTHORITY\LOCAL SERVICE`: true,
		`AVD-HOST-07\jdoe`:           false,
		"":                           true,
		"unknown":                    true,
	} {
		if got := device.IsServiceAccount(m, user); got != want {
			t.Errorf("IsServiceAccount(%q) = %v, want %v", user, got, want)
		}
	}
}
