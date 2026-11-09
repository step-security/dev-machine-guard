package telemetry

import (
	"context"
	"encoding/json"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"net/http"
	"net/http/httptest"
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
		CustomerID:       "c",
		DeviceID:         "avd-host-07-jdoe",
		SerialNumber:     "0000-0012-3456-7890",
		DeviceIDSource:   "config",
		DeviceIDTemplate: "{hostname}",
		DeviceTag:        "avd-pool-eu",
		UserIdentity:     `CONTOSO\JDoe`,
		UserToken:        "jdoe-8c4e2c054b47",
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
		`"device_id_template":"{hostname}"`,
		`"device_tag":"avd-pool-eu"`,
		`"user_token":"jdoe-8c4e2c054b47"`,
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
	if strings.Contains(string(b), "device_id_template") {
		t.Errorf("empty template must be omitted: %s", b)
	}
	if strings.Contains(string(b), "user_token") {
		t.Errorf("an empty user token (a service account) must be omitted: %s", b)
	}
	// device_tag is always present: an empty value tells the backend the tag
	// was cleared, while an older agent omits the key altogether.
	if !strings.Contains(string(b), `"device_tag":""`) {
		t.Errorf("empty device_tag must still be serialized: %s", b)
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

func TestPayload_CarriesVirtualization(t *testing.T) {
	v := &model.Virtualization{Type: model.VirtualizationVirtual, Vendor: "azure", Source: "imds"}
	data, err := json.Marshal(&Payload{DeviceID: "d", Virtualization: v})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"virtualization":{"type":"virtual","vendor":"azure","source":"imds"}`) {
		t.Errorf("virtualization missing from payload: %s", data)
	}
	bare, _ := json.Marshal(&Payload{DeviceID: "d"})
	if strings.Contains(string(bare), "virtualization") {
		t.Errorf("nil virtualization must be omitted: %s", bare)
	}
}

// Every beacon of a run carries the session's user token, the same value the
// upload reports, so the backend files the run under the right user of the
// device; a service account (no token) omits it.
func TestRunStatusBody_CarriesTheUserToken(t *testing.T) {
	t.Cleanup(func() { setRunUserToken("") })
	setRunUserToken("jdoe-8c4e2c054b47")
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		bodies = append(bodies, m)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	prevEndpoint, prevKey, prevCustomer := config.APIEndpoint, config.APIKey, config.CustomerID
	config.APIEndpoint, config.APIKey, config.CustomerID = srv.URL, "k", "acme"
	t.Cleanup(func() { config.APIEndpoint, config.APIKey, config.CustomerID = prevEndpoint, prevKey, prevCustomer })

	reportRunStatus(context.Background(), progress.NewNoop(), "exec-1", "SER1", runStatusStarted, "", "install")
	postProgress(context.Background(), progress.NewNoop(), "exec-1", "SER1", "install", RunStatusInfo{})
	setRunUserToken("")
	reportRunStatus(context.Background(), progress.NewNoop(), "exec-1", "SER1", runStatusFailed, "boom", "install")
	if len(bodies) != 3 {
		t.Fatalf("got %d beacons, want 3", len(bodies))
	}
	for i := 0; i < 2; i++ {
		if bodies[i]["user_token"] != "jdoe-8c4e2c054b47" {
			t.Errorf("beacon %d user_token = %v, want jdoe-8c4e2c054b47", i, bodies[i]["user_token"])
		}
	}
	if _, present := bodies[2]["user_token"]; present {
		t.Errorf("a run without a session user must omit user_token: %v", bodies[2])
	}
}
