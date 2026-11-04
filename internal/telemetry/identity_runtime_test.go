package telemetry

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestIdentityRuntimeTelemetryOut(t *testing.T) {
	// This exercises production scan/payload assembly and its local output path.
	// Only the singleton lock is substituted; every OS probe uses executor.Mock.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	withTestConfig(t, server.URL)
	previous := config.UserID
	t.Cleanup(func() { config.UserID = previous })
	for _, tc := range []struct {
		name, user, configured, serial     string
		missingUser, missingDevice, noUser bool
	}{
		{"both_present", "alice", "", "HW-123", false, false, false},
		{"missing_user", "root", "", "HW-123", true, false, true},

		{"configured_no_session", "root", "configured-id", "HW-123", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)
			t.Setenv("USERPROFILE", dir)
			t.Setenv("STEPSECURITY_HOME", dir)
			t.Setenv("STEPSEC_MAX_SCAN_DURATION", "5s")
			config.UserID = tc.configured
			m := executor.NewMock()
			m.SetGOOS("linux")
			m.SetUsername(tc.user)
			m.SetHomeDir(dir)
			if tc.serial != "" {
				m.SetFile("/sys/class/dmi/id/product_serial", []byte(tc.serial))
			}
			disabled := false
			output := filepath.Join(dir, "telemetry.json")
			cfg := &cli.Config{TelemetryOutFile: output, SearchDirs: []string{dir}, EnableNPMScan: &disabled, EnableBrewScan: &disabled, EnablePythonScan: &disabled}
			device.ResetIDCache()
			t.Cleanup(device.ResetIDCache)
			defer lock.SetTargetForTest(filepath.Join(dir, "scanner.lock"))()
			if err := Run(m, progress.NewLogger(progress.LevelWarn), cfg); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(config.ConfigFilePath()); !os.IsNotExist(err) {
				t.Fatalf("scan unexpectedly persisted an identity/config: %v", err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			for field, want := range map[string]bool{"user_id_missing": tc.missingUser, "device_id_missing": tc.missingDevice, "no_user_logged_in": tc.noUser} {
				value, exists := raw[field]
				if !exists {
					t.Fatalf("runtime omitted %s", field)
				}
				var got bool
				if err := json.Unmarshal(value, &got); err != nil || got != want {
					t.Fatalf("runtime %s=%s want %v", field, value, want)
				}
			}
			var gotUser string
			if err := json.Unmarshal(raw["user_identity"], &gotUser); err != nil {
				t.Fatal(err)
			}
			wantUser := tc.user
			if tc.missingUser {
				wantUser = "unknown"
			}
			if tc.configured != "" {
				wantUser = tc.configured
			}
			if tc.missingUser {
				var logs ExecutionLogs
				if err := json.Unmarshal(raw["execution_logs"], &logs); err != nil {
					t.Fatal(err)
				}
				output, err := base64.StdEncoding.DecodeString(logs.OutputBase64)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(output), "Run this executable with: configure --non-interactive --user-id <ID>") {
					t.Fatalf("recovery instruction assumes an alias: %s", output)
				}
			}
			if gotUser != wantUser {
				t.Fatalf("runtime user %q want %q", gotUser, wantUser)
			}
		})
	}
}

func TestIdentityRuntimeMissingDeviceKeepsUploadGate(t *testing.T) {
	// Current backend transport requires a device key. A missing-ID payload can
	// be serialized, but the production runtime must not upload under a shared
	// placeholder or erase this gate without backend support.
	var uploadRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/telemetry/upload-url") {
			uploadRequests.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	withTestConfig(t, server.URL)
	previousUser, previousDevice := config.UserID, config.DeviceID
	config.UserID = ""
	config.DeviceID = ""
	t.Cleanup(func() { config.UserID = previousUser; config.DeviceID = previousDevice })
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Setenv("STEPSECURITY_HOME", dir)
	device.ResetIDCache()
	t.Cleanup(device.ResetIDCache)
	defer lock.SetTargetForTest(filepath.Join(dir, "scanner.lock"))()
	m := executor.NewMock()
	m.SetGOOS("linux")
	m.SetUsername("root")
	m.SetHomeDir(dir)
	source := struct{ executor.Executor }{m} // no persistence capability for fallback IDs
	err := Run(source, progress.NewNoop(), &cli.Config{})
	if err == nil || !strings.Contains(err.Error(), "device identity could not be determined") {
		t.Fatalf("missing-device gate: %v", err)
	}
	if uploadRequests.Load() != 0 {
		t.Fatal("runtime uploaded without a usable device identity")
	}
}
