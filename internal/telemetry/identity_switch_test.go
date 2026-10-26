package telemetry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

type retireCall struct {
	Path   string
	Reason string
}

func retireServer(t *testing.T) (*httptest.Server, *[]retireCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []retireCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		calls = append(calls, retireCall{Path: r.URL.Path, Reason: body["reason"]})
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"retired"}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func writeMarker(t *testing.T, dir, reason string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "multi-user.json"), []byte(`{"since":1,"reason":"`+reason+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
}

func autoDevice(serial string) *model.Device {
	return &model.Device{SerialNumber: serial, DeviceID: "host-jdoe", DeviceIDSource: device.IdentitySourceAuto, Platform: model.PlatformWindows}
}

func TestRetireSerialRowOnIdentitySwitch_OnceAfterSecondUser(t *testing.T) {
	srv, calls := retireServer(t)
	t.Cleanup(withEnterpriseConfig(t, srv.URL))
	dir := t.TempDir()
	t.Cleanup(device.SetMachineStateDirForTest(dir))
	writeMarker(t, dir, "users")
	exec := executor.NewMock()
	exec.SetGOOS(model.PlatformWindows)
	log := progress.NewNoop()

	retireSerialRowOnIdentitySwitch(context.Background(), exec, log, autoDevice("SER1"), nil)
	retireSerialRowOnIdentitySwitch(context.Background(), exec, log, autoDevice("SER1"), nil)
	if len(*calls) != 1 {
		t.Fatalf("expected exactly one retire, got %d: %+v", len(*calls), *calls)
	}
	if c := (*calls)[0]; c.Path != "/v1/test-customer/developer-mdm-agent/devices/SER1/retire" || c.Reason != "identity_changed" {
		t.Errorf("unexpected call %+v", c)
	}
}

func TestRetireSerialRowOnIdentitySwitch_UpgradedHostUsesLastRun(t *testing.T) {
	srv, calls := retireServer(t)
	t.Cleanup(withEnterpriseConfig(t, srv.URL))
	dir := t.TempDir()
	t.Cleanup(device.SetMachineStateDirForTest(dir))
	writeMarker(t, dir, "edition")
	exec := executor.NewMock()
	exec.SetGOOS(model.PlatformWindows)
	log := progress.NewNoop()

	// No evidence of a serial row yet: nothing to retire.
	retireSerialRowOnIdentitySwitch(context.Background(), exec, log, autoDevice("SER1"), nil)
	if len(*calls) != 0 {
		t.Fatalf("edition switch without a prior serial run must not retire, got %+v", *calls)
	}
	// The machine-wide last-run.json says this host checked in as SER1 before.
	path := filepath.Join(dir, heartbeat.Filename)
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"run_gate":{"device_id":"SER1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	retireSerialRowOnIdentitySwitch(context.Background(), exec, log, autoDevice("SER1"), nil)
	if len(*calls) != 1 || (*calls)[0].Reason != "identity_changed" {
		t.Fatalf("expected one retire of the upgraded host's serial row, got %+v", *calls)
	}
}

func TestRetireSerialRowOnIdentitySwitch_SkipsNonAutoAndGuests(t *testing.T) {
	srv, calls := retireServer(t)
	t.Cleanup(withEnterpriseConfig(t, srv.URL))
	dir := t.TempDir()
	t.Cleanup(device.SetMachineStateDirForTest(dir))
	writeMarker(t, dir, "users")
	exec := executor.NewMock()
	exec.SetGOOS(model.PlatformWindows)
	log := progress.NewNoop()

	configured := autoDevice("SER1")
	configured.DeviceIDSource = device.IdentitySourceConfig
	retireSerialRowOnIdentitySwitch(context.Background(), exec, log, configured, nil)
	retireSerialRowOnIdentitySwitch(context.Background(), exec, log, autoDevice("SER1"), &model.WSLGuest{HostDeviceID: "SER1", DistroID: "x"})
	if len(*calls) != 0 {
		t.Errorf("configured identities and WSL guests must never retire, got %+v", *calls)
	}
}

func TestRetireSerialRowOnIdentitySwitch_FailureIsNotRecorded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
	t.Cleanup(srv.Close)
	t.Cleanup(withEnterpriseConfig(t, srv.URL))
	dir := t.TempDir()
	t.Cleanup(device.SetMachineStateDirForTest(dir))
	writeMarker(t, dir, "users")
	exec := executor.NewMock()
	exec.SetGOOS(model.PlatformWindows)
	retireSerialRowOnIdentitySwitch(context.Background(), exec, progress.NewNoop(), autoDevice("SER1"), nil)
	if !device.SerialRowRetirePending("SER1", "") {
		t.Error("a failed retire must stay pending for the next run")
	}
}
