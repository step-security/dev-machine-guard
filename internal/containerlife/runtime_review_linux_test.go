//go:build linux

package containerlife

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestContainerCredentialPrecedence(t *testing.T) {
	oldCustomer, oldEndpoint, oldKey := config.CustomerID, config.APIEndpoint, config.APIKey
	defer func() { config.CustomerID, config.APIEndpoint, config.APIKey = oldCustomer, oldEndpoint, oldKey }()
	t.Setenv("HOME", t.TempDir())
	for _, key := range []string{"DMG_CUSTOMER_ID", "DMG_API_ENDPOINT", "DMG_API_KEY"} {
		t.Setenv(key, "")
	}
	config.CustomerID, config.APIEndpoint, config.APIKey = "embedded-org", "https://embedded.example/", "embedded-key"
	r := runtime{dir: filepath.Join(t.TempDir(), "state")}
	if err := r.setup(); err != nil {
		t.Fatalf("embedded-only enrollment failed: %v", err)
	}
	if r.cfg.CustomerID != "embedded-org" || r.cfg.APIKey != "embedded-key" {
		t.Fatal("embedded credentials not used")
	}
	t.Setenv("DMG_CUSTOMER_ID", "env-org")
	t.Setenv("DMG_API_ENDPOINT", "https://env.example")
	t.Setenv("DMG_API_KEY", "env-key")
	other := runtime{dir: filepath.Join(t.TempDir(), "state")}
	if err := other.setup(); err != nil {
		t.Fatal(err)
	}
	if other.cfg.CustomerID != "embedded-org" || other.cfg.APIKey != "embedded-key" {
		t.Fatal("environment overrode embedded credentials")
	}
	config.CustomerID, config.APIEndpoint, config.APIKey = "updated-org", "https://updated.example", "updated-key"
	if err := r.load(); err != nil {
		t.Fatal(err)
	}
	if r.cfg.CustomerID != "updated-org" || r.cfg.APIKey != "updated-key" {
		t.Fatal("reload ignored updated embedded credentials")
	}
}

func TestStopRequiresAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		ok         bool
	}{
		{"missing", `{}`, false},
		{"wrong-state", `{"container_lifecycle":{"status":"active","generation":1,"sequence":1}}`, false},
		{"rejected", `{"accepted":false}`, false},
		{"accepted", `{"accepted":true}`, true},
		{"already-stopped", `{"accepted":false,"container_lifecycle":{"status":"stopped","generation":1,"sequence":1}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
			defer server.Close()
			r := runtime{dir: t.TempDir(), client: server.Client(), state: runtimeState{DeviceID: "test", Generation: 1, Sequence: 1}}
			r.cfg.APIEndpoint = server.URL
			if err := r.event("stop"); (err == nil) != tc.ok {
				t.Fatalf("stop result=%v, want accepted=%t", err, tc.ok)
			}
		})
	}
}

func reviewRuntime(t *testing.T, handler http.HandlerFunc) *runtime {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	dir, err := os.MkdirTemp("", "dmg-review-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("HOME", dir)
	t.Setenv("DMG_CUSTOMER_ID", "test-org")
	t.Setenv("DMG_API_ENDPOINT", server.URL)
	t.Setenv("DMG_API_KEY", "test-key")
	r := &runtime{dir: dir, client: server.Client(), binary: "/bin/true"}
	if err = r.setup(); err != nil {
		t.Fatal(err)
	}
	return r
}
func acceptReviewEvent(w http.ResponseWriter, _ *http.Request) {
	accepted := true
	_ = json.NewEncoder(w).Encode(model.ContainerLifecycleResponse{Accepted: &accepted, Lifecycle: model.ContainerLifecycle{Generation: 1}})
}

func TestScanPinsIdentityAndLogsExitFailure(t *testing.T) {
	r := reviewRuntime(t, acceptReviewEvent)
	t.Setenv("STEPSEC_DEVICE_ID", "shared-host-id")
	t.Setenv("DMG_TEST_RESULT", filepath.Join(r.dir, "scan-result"))
	r.binary = filepath.Join(r.dir, "scan")
	if err := os.WriteFile(r.binary, []byte("#!/bin/sh\nprintf '%s' \"$STEPSEC_DEVICE_ID\" > \"$DMG_TEST_RESULT\"\necho scan-diagnostic >&2\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.run() }()
	waitForShutdownCondition(t, func() bool { b, _ := os.ReadFile(filepath.Join(r.dir, "scan-result")); return len(b) > 0 })
	waitForShutdownCondition(t, func() bool {
		b, _ := os.ReadFile(filepath.Join(r.dir, "runtime.log"))
		return strings.Contains(string(b), "exit code 7")
	})
	if err := r.control("stop", 5*time.Second); err != nil {
		t.Error(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime did not stop")
	}
	b, _ := os.ReadFile(filepath.Join(r.dir, "scan-result"))
	if string(b) != r.state.DeviceID {
		t.Errorf("scan identity %q differs from lifecycle %q", b, r.state.DeviceID)
	}
	if os.Getenv("STEPSEC_DEVICE_ID") != "shared-host-id" {
		t.Error("parent environment mutated")
	}
	log, err := os.ReadFile(filepath.Join(r.dir, "runtime.log"))
	if err != nil || !strings.Contains(string(log), "exit code 7") || !strings.Contains(string(log), "scan-diagnostic") {
		t.Errorf("scan failure not logged: %s %v", log, err)
	}
}

func TestStartupFailureIsLogged(t *testing.T) {
	r := reviewRuntime(t, acceptReviewEvent)
	if err := os.WriteFile(r.statePath(), []byte("invalid-state"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.run(); err == nil {
		t.Fatal("invalid state accepted")
	}
	log, err := os.ReadFile(filepath.Join(r.dir, "runtime.log"))
	if err != nil || !strings.Contains(string(log), "invalid character") {
		t.Errorf("startup failure missing: %s %v", log, err)
	}
}

func TestStopWaitsForHeartbeat(t *testing.T) {
	heartbeat := make(chan struct{})
	release := make(chan struct{})
	r := reviewRuntime(t, func(w http.ResponseWriter, req *http.Request) {
		var e model.ContainerLifecycleEvent
		_ = json.NewDecoder(req.Body).Decode(&e)
		if e.Event == "heartbeat" {
			close(heartbeat)
			<-release
		}
		acceptReviewEvent(w, req)
	})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- r.run() }()
	select {
	case <-heartbeat:
	case <-time.After(35 * time.Second):
		t.Fatal("heartbeat not observed")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- r.control("stop", 5*time.Second) }()
	// Keep the heartbeat in flight beyond the old one-second handoff timeout.
	select {
	case err := <-stopped:
		close(release)
		t.Fatalf("stop discarded during heartbeat: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-stopped:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stop not handled")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker still running")
	}
}

func TestRuntimeLogBoundedAndPrivate(t *testing.T) {
	r := runtime{dir: t.TempDir()}
	r.cfg.APIKey = "private-test-key"
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = null
	defer func() { os.Stderr = original; _ = null.Close() }()
	r.logError("%s", strings.Repeat("x", runtimeLogLimit+100))
	r.logError("credential %s", r.cfg.APIKey)
	for _, name := range []string{"runtime.log", "runtime.log.prev"} {
		info, err := os.Stat(filepath.Join(r.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Size() > runtimeLogLimit || info.Mode().Perm() != 0600 {
			t.Fatalf("unbounded or public log: %s size=%d mode=%v", name, info.Size(), info.Mode())
		}
	}
	b, err := os.ReadFile(filepath.Join(r.dir, "runtime.log"))
	if err != nil || strings.Contains(string(b), r.cfg.APIKey) || !strings.Contains(string(b), "[redacted]") {
		t.Fatalf("log redaction failed: %v", err)
	}
}

func TestContainerEnvironmentOverridesFileCredentials(t *testing.T) {
	oldCustomer, oldEndpoint, oldKey := config.CustomerID, config.APIEndpoint, config.APIKey
	defer func() { config.CustomerID, config.APIEndpoint, config.APIKey = oldCustomer, oldEndpoint, oldKey }()
	config.CustomerID, config.APIEndpoint, config.APIKey = "{{CUSTOMER_ID}}", "{{API_ENDPOINT}}", "{{API_KEY}}"
	t.Setenv("HOME", t.TempDir())
	path := config.ConfigFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(config.ConfigFile{CustomerID: "file-org", APIEndpoint: "https://file.example", APIKey: "file-key"})
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DMG_CUSTOMER_ID", "env-org")
	t.Setenv("DMG_API_ENDPOINT", "https://env.example/")
	t.Setenv("DMG_API_KEY", "env-key")
	r := runtime{dir: filepath.Join(t.TempDir(), "state")}
	if err := r.setup(); err != nil {
		t.Fatal(err)
	}
	if r.cfg.CustomerID != "env-org" || r.cfg.APIEndpoint != "https://env.example" || r.cfg.APIKey != "env-key" {
		t.Fatal("environment credentials not applied")
	}
	b, err := os.ReadFile(r.configPath())
	if err != nil {
		t.Fatal(err)
	}
	var stored config.ConfigFile
	if err = json.Unmarshal(b, &stored); err != nil {
		t.Fatal(err)
	}
	if got := config.EffectiveCredentials(stored); got.CustomerID != r.cfg.CustomerID || got.APIEndpoint != r.cfg.APIEndpoint || got.APIKey != r.cfg.APIKey {
		t.Fatal("scan config differs from lifecycle credentials")
	}
	for _, key := range []string{"DMG_CUSTOMER_ID", "DMG_API_ENDPOINT", "DMG_API_KEY"} {
		t.Setenv(key, "{{UNRESOLVED}}")
	}
	missing := runtime{dir: filepath.Join(t.TempDir(), "state")}
	if err := missing.setup(); err == nil {
		t.Fatal("accepted unresolved credentials")
	}
}
