package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

func TestCustomDeviceIDPreflightRejectsAnotherMachine(t *testing.T) {
	oldID, oldURL, oldKey, oldCustomer := config.DeviceID, config.APIEndpoint, config.APIKey, config.CustomerID
	t.Cleanup(func() {
		config.DeviceID, config.APIEndpoint, config.APIKey, config.CustomerID = oldID, oldURL, oldKey, oldCustomer
	})
	var mu sync.Mutex
	owner := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var req struct {
			MachineID string `json:"machine_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if owner == "" {
			owner = req.MachineID
		}
		if owner != req.MachineID {
			w.WriteHeader(http.StatusConflict)
			return
		}
		_, _ = w.Write([]byte(`{"device_id":"dev-123","device_identity_verified":true}`))
	}))
	defer srv.Close()
	config.DeviceID, config.APIEndpoint, config.APIKey, config.CustomerID = "dev-123", srv.URL, "test-key", "customer"
	for _, tc := range []struct {
		serial  string
		wantErr bool
	}{{"SER-A", false}, {"SER-B", true}} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		mock := executor.NewMock()
		mock.SetGOOS("linux")
		mock.SetFile("/sys/class/dmi/id/product_serial", []byte(tc.serial))
		cfg := &cli.Config{Command: "send-telemetry"}
		err := verifyCustomDeviceID(mock, cfg)
		if (err != nil) != tc.wantErr {
			t.Fatalf("preflight for %s: %v", tc.serial, err)
		}
		if tc.wantErr && cfg.DeviceIdentity != "" {
			t.Fatal("conflicting machine received an ownership proof")
		}
		if !tc.wantErr && cfg.DeviceIdentity == "" {
			t.Fatal("verified machine has no ownership proof")
		}
	}
}

func TestCustomDeviceIDAllowsOfflineReconfiguration(t *testing.T) {
	oldID, oldKey := config.DeviceID, config.APIKey
	t.Cleanup(func() { config.DeviceID, config.APIKey = oldID, oldKey })
	config.DeviceID, config.APIKey = "dev-123", "test-key"
	for _, command := range []string{"configure", "configure show", "uninstall", "hooks uninstall"} {
		if err := verifyCustomDeviceID(executor.NewMock(), &cli.Config{Command: command}); err != nil {
			t.Fatalf("%s: %v", command, err)
		}
	}
}
