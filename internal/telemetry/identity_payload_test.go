package telemetry

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// TestPayload_DeviceIDAndSerialWireContract locks the backend-facing shape: a
// configured identity ships as device_id with its source, while serial_number
// stays the probed hardware serial so a rebuilt host is still recognisable.
func TestPayload_DeviceIDAndSerialWireContract(t *testing.T) {
	p := &Payload{
		CustomerID:     "c",
		DeviceID:       "avd-host-07-jdoe",
		SerialNumber:   "0000-0012-3456-7890",
		DeviceIDSource: "config",
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`"device_id":"avd-host-07-jdoe"`,
		`"serial_number":"0000-0012-3456-7890"`,
		`"device_id_source":"config"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("payload missing %s: %s", want, s)
		}
	}
	// Legacy shape (no template): the source is omitted only when empty, and
	// the serial-sourced payload carries the same value in both fields.
	b, _ = json.Marshal(&Payload{DeviceID: "SER", SerialNumber: "SER"})
	if strings.Contains(string(b), "device_id_source") {
		t.Errorf("empty source must be omitted: %s", b)
	}
}

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
