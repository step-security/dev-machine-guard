package telemetry

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	hookidentity "github.com/step-security/dev-machine-guard/internal/aiagents/identity"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func TestDeviceIdentityTelemetryWire(t *testing.T) {
	for _, tc := range []struct {
		name, configured, user, email, serial string
		userMissing, deviceMissing, noUser    bool
	}{
		{"detected_both", "", "alice", "", "HW-123", false, false, false},
		{"missing_user", "", "root", "", "HW-123", true, false, true},
		{"missing_device", "", "alice", "", "", false, true, false},
		{"missing_both", "", "root", "", "", true, true, true},
		{"configured_no_session", "team+abc@example.com", "root", "other@example.com", "HW-123", false, false, true},
		{"email_no_session", "", "root", "email@example.com", "HW-123", false, false, true},
		{"existing_os_format", "", "DOMAIN\\alice", "", "HW-123", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			previous := config.UserID
			device.ResetIDCache()
			t.Cleanup(device.ResetIDCache)
			config.UserID = tc.configured
			t.Cleanup(func() { config.UserID = previous })
			m := executor.NewMock()
			m.SetGOOS("linux")
			m.SetUsername(tc.user)
			m.SetEnv("USER_EMAIL", tc.email)
			if tc.serial != "" {
				m.SetFile("/sys/class/dmi/id/product_serial", []byte(tc.serial))
			}
			source := struct{ executor.Executor }{m}
			dev := device.Gather(context.Background(), source)
			envelope := hookidentity.Resolve(context.Background(), source, "test-customer")
			if envelope.UserIdentity != dev.UserIdentity || envelope.DeviceID != device.ID(dev) && !(device.ID(dev) == "" && envelope.DeviceID == "unknown") {
				t.Fatal("scan/hook disagreement")
			}
			p := &Payload{CustomerID: "test-customer"}
			p.applyDevice(dev, device.ID(dev), dev.SerialNumber)
			if p.UserIDMissing != tc.userMissing || p.DeviceIDMissing != tc.deviceMissing || p.NoUserLoggedIn != tc.noUser {
				t.Fatalf("flags: %+v", p)
			}
			if tc.configured != "" && p.UserIdentity != tc.configured {
				t.Fatal("configured identity lost")
			}
			account, err := m.CurrentUser()
			if err != nil || account.Username != tc.user {
				t.Fatal("attribution changed OS account")
			}
			var mu sync.Mutex
			var captured map[string]json.RawMessage
			var uploadID, notifyID string
			put := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gz, err := gzip.NewReader(r.Body)
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				defer gz.Close()
				var raw map[string]json.RawMessage
				if err := json.NewDecoder(gz).Decode(&raw); err != nil {
					t.Error(err)
				}
				mu.Lock()
				captured = raw
				mu.Unlock()
				w.Header().Set("x-amz-request-id", "TEST")
				w.Header().Set("x-amz-id-2", "TEST")
			}))
			defer put.Close()
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var req map[string]json.RawMessage
				if err := json.Unmarshal(body, &req); err != nil {
					t.Error(err)
				}
				switch {
				case strings.HasSuffix(r.URL.Path, "/telemetry/upload-url"):
					mu.Lock()
					if err := json.Unmarshal(req["device_id"], &uploadID); err != nil {
						t.Error(err)
					}
					mu.Unlock()
					if err := json.NewEncoder(w).Encode(map[string]string{"upload_url": put.URL, "s3_key": "fixture.json.gz"}); err != nil {
						t.Error(err)
					}
				case strings.HasSuffix(r.URL.Path, "/telemetry/process-uploaded"):
					mu.Lock()
					if err := json.Unmarshal(req["device_id"], &notifyID); err != nil {
						t.Error(err)
					}
					mu.Unlock()
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer backend.Close()
			withTestConfig(t, backend.URL)
			if _, err := uploadToS3(context.Background(), progress.NewNoop(), p, "test-execution", nil, nil); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			for key, want := range map[string]bool{"user_id_missing": tc.userMissing, "device_id_missing": tc.deviceMissing, "no_user_logged_in": tc.noUser} {
				raw, ok := captured[key]
				if !ok {
					t.Fatalf("missing explicit field %s", key)
				}
				var got bool
				if err := json.Unmarshal(raw, &got); err != nil || got != want {
					t.Fatalf("%s=%s want %v", key, raw, want)
				}
			}
			if uploadID != device.ID(dev) || notifyID != device.ID(dev) {
				t.Fatalf("transport device mismatch: %q %q", uploadID, notifyID)
			}
			var gotUser string
			if err := json.Unmarshal(captured["user_identity"], &gotUser); err != nil || gotUser != dev.UserIdentity {
				t.Fatal("wire attribution mismatch")
			}
		})
	}
}

func TestIdentityStampPreservesEffectiveDeviceAndWSLSerial(t *testing.T) {
	for _, tc := range []struct{ deviceID, serialIdentity string }{{"configured-device", "hardware-serial"}, {"host-device#wsl#Ubuntu", "host-device#wsl#Ubuntu"}, {"", "unknown"}} {
		p := &Payload{}
		p.applyDevice(model.Device{SerialNumber: "hardware-serial", UserIdentity: "user-id"}, tc.deviceID, tc.serialIdentity)
		if p.DeviceID != tc.deviceID || p.SerialNumber != tc.serialIdentity || p.DeviceIDMissing != (tc.deviceID == "") {
			t.Fatalf("effective identity overwritten: %+v", p)
		}
	}
}
