package deviceidentity

import (
	"context"
	"encoding/json"
	"github.com/step-security/dev-machine-guard/internal/config"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVerify(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{"verified", 200, `{"device_id":"dev-123","device_identity_verified":true}`, false},
		{"collision", 409, `{"code":"device_id_conflict"}`, true},
		{"old backend", 200, `{"upload_url":"https://example.invalid/upload","s3_key":"unused"}`, true},
		{"different ID", 200, `{"device_id":"other","device_identity_verified":true}`, true},
		{"backend failure", 503, `{}`, true},
		{"malformed response", 200, `{`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected, _ := ownerID("SERIAL-A")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var req struct {
					MachineID     string `json:"machine_id"`
					DeviceID      string `json:"device_id"`
					IdentityCheck bool   `json:"identity_check"`
				}
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Error(err)
				}
				if r.Method != http.MethodPost || req.MachineID != expected || req.DeviceID != "dev-123" || !req.IdentityCheck {
					t.Errorf("unexpected identity request: %+v", req)
				}
				if r.Header.Get("Authorization") != "Bearer test-key" {
					t.Error("missing agent authentication")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			got, err := Verify(context.Background(), srv.URL, "test-key", "customer", "dev-123", "SERIAL-A")
			if (err != nil) != tc.wantErr {
				t.Fatalf("Verify error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != expected {
				t.Fatalf("owner = %q, want %q", got, expected)
			}
		})
	}
}

func TestOwnerIdentityPersistsWithoutSerial(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	first, err := ownerID("unknown")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ownerID("unknown")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("owner identity changed between runs")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	other, err := ownerID("unknown")
	if err != nil {
		t.Fatal(err)
	}
	if first == other {
		t.Fatal("different installations share owner identity")
	}
}

func TestOwnerIdentityRejectsCorruptState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if _, err := ownerID("unknown"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".stepsecurity", "device-owner-id"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerID("unknown"); err == nil {
		t.Fatal("corrupt identity must not be silently replaced")
	}
}

func TestOwnerIdentitySurvivesSerialAvailabilityChanges(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	first, err := ownerID("unknown")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ownerID("SERIAL-NEW")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("learning a serial replaced the persisted owner identity")
	}
}

func TestOwnerIdentityDoesNotFollowSharedConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	shared := filepath.Join(t.TempDir(), "config.json")
	config.SetFileOverride(shared)
	t.Cleanup(func() { config.SetFileOverride("") })
	if _, err := ownerID("SERIAL-A"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(shared), "device-owner-id")); !os.IsNotExist(err) {
		t.Fatal("owner identity was written beside the shared config")
	}
	if _, err := os.Stat(filepath.Join(home, ".stepsecurity", "device-owner-id")); err != nil {
		t.Fatal(err)
	}
}
