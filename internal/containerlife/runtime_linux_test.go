//go:build linux

package containerlife

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestSetupIdentityAndCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DMG_CUSTOMER_ID", "test-org")
	t.Setenv("DMG_API_ENDPOINT", "https://example.test")
	t.Setenv("DMG_API_KEY", "test-key")
	a := runtime{dir: filepath.Join(t.TempDir(), "a")}
	if err := a.setup(); err != nil {
		t.Fatal(err)
	}
	id := a.state.DeviceID
	if err := a.setup(); err != nil {
		t.Fatal(err)
	}
	if a.state.DeviceID != id || a.cfg.DeviceID != id {
		t.Fatal("setup changed identity")
	}
	b := runtime{dir: filepath.Join(t.TempDir(), "b")}
	if err := b.setup(); err != nil {
		t.Fatal(err)
	}
	if b.state.DeviceID == id {
		t.Fatal("containers share identity")
	}
	info, err := os.Stat(a.configPath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("credentials are not private")
	}
}
func TestEventRetriesWithStableIdentity(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Error("missing auth")
		}
		var event model.ContainerLifecycleEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
		}
		if event.StartID != "stable-start" || event.DeviceID != "container-test" {
			t.Error("retry changed identity")
		}
		attempts++
		if attempts < 3 {
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(model.ContainerLifecycleResponse{Lifecycle: model.ContainerLifecycle{Generation: 7}})
	}))
	defer server.Close()
	r := runtime{dir: t.TempDir(), client: server.Client(), state: runtimeState{DeviceID: "container-test", StartID: "stable-start"}}
	r.cfg.CustomerID = "test-org"
	r.cfg.APIKey = "test-key"
	r.cfg.APIEndpoint = server.URL
	if err := r.event("start"); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || r.state.Generation != 7 {
		t.Fatal("start acknowledgement not persisted")
	}
	var persisted runtimeState
	b, err := os.ReadFile(r.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Generation != 7 {
		t.Fatal("lost generation")
	}
}
func TestRuntimeLockExclusive(t *testing.T) {
	r := runtime{dir: t.TempDir()}
	f, err := r.acquire("runtime.lock")
	if err != nil {
		t.Fatal(err)
	}
	if second, err := r.acquire("runtime.lock"); err == nil {
		second.Close()
		t.Fatal("second worker acquired lock")
	}
	f.Close()
	next, err := r.acquire("runtime.lock")
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}

func TestMetadataSetupPreservesRunningState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("DMG_CUSTOMER_ID", "test-org")
	t.Setenv("DMG_API_ENDPOINT", "https://example.test")
	t.Setenv("DMG_API_KEY", "test-key")
	dir := t.TempDir()
	if err := Run([]string{"setup", "--state-dir", dir, "--workspace-name", "widgets", "--repository-url", "https://github.com/example-org/widgets", "--environment", "devcontainer"}); err != nil {
		t.Fatal(err)
	}
	r := runtime{dir: dir}
	if err := r.load(); err != nil {
		t.Fatal(err)
	}
	r.state.Generation = 7
	r.state.Sequence = 22
	if err := r.save(); err != nil {
		t.Fatal(err)
	}
	before := r.state
	if err := Run([]string{"setup", "--state-dir", dir, "--workspace-name", "next", "--repository-url", ""}); err != nil {
		t.Fatal(err)
	}
	if err := r.load(); err != nil {
		t.Fatal(err)
	}
	if r.state != before {
		t.Fatal("metadata setup changed runtime identity or generation")
	}
	m, err := readMetadata(dir)
	if err != nil || m.WorkspaceName != "next" || m.RepositoryURL != "" || m.Environment != "devcontainer" {
		t.Fatalf("metadata update: %+v %v", m, err)
	}
	info, err := os.Stat(filepath.Join(dir, "metadata.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("metadata not private")
	}
	if err := Run([]string{"setup", "--state-dir", dir, "--repository-url", "https://secret@example.com/widgets"}); err == nil {
		t.Fatal("unsafe input accepted")
	}
	unchanged, err := readMetadata(dir)
	if err != nil || *unchanged != *m {
		t.Fatal("invalid setup altered metadata")
	}
}

func TestStartOnlyMetadata(t *testing.T) {
	expected := model.ContainerMetadata{WorkspaceName: "widgets", Environment: "docker"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event model.ContainerLifecycleEvent
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			t.Error(err)
		}
		if event.Event == "start" {
			if event.Metadata == nil || *event.Metadata != expected {
				t.Error("start metadata missing")
			}
		} else if event.Metadata != nil {
			t.Error("heartbeat carried metadata")
		}
		_ = json.NewEncoder(w).Encode(model.ContainerLifecycleResponse{Lifecycle: model.ContainerLifecycle{Generation: 1}})
	}))
	defer server.Close()
	r := runtime{dir: t.TempDir(), client: server.Client(), metadata: &expected, state: runtimeState{DeviceID: "test", StartID: "test-start"}}
	r.cfg.APIEndpoint = server.URL
	r.cfg.CustomerID = "test-org"
	if err := r.event("start"); err != nil {
		t.Fatal(err)
	}
	if err := r.event("heartbeat"); err != nil {
		t.Fatal(err)
	}
}
