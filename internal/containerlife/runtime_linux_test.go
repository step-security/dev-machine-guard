//go:build linux

package containerlife

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
	"golang.org/x/sys/unix"
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

// Exercise shutdown while the listener is reading an idle client and a real
// scan subprocess is running. Both successful and failed stop reports must clean up.
func TestRuntimeShutdownClosesIdleClient(t *testing.T) {
	for _, failStop := range []bool{false, true} {
		t.Run(fmt.Sprintf("stop_error_%t", failStop), func(t *testing.T) {
			stopReceived := make(chan struct{})
			releaseStop := make(chan struct{})

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var event model.ContainerLifecycleEvent
				if err := json.NewDecoder(req.Body).Decode(&event); err != nil {
					t.Error(err)
					return
				}
				if event.Event == "stop" {
					close(stopReceived)
					<-releaseStop
					if failStop {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
				}
				_ = json.NewEncoder(w).Encode(model.ContainerLifecycleResponse{Lifecycle: model.ContainerLifecycle{Generation: 1}})
			}))
			defer server.Close()
			defer func() {
				select {
				case <-releaseStop:
				default:
					close(releaseStop)
				}
			}()
			// Keep the Unix socket path below the platform limit.
			dir, err := os.MkdirTemp("", "dmg-stop-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			t.Setenv("HOME", dir)
			t.Setenv("DMG_CUSTOMER_ID", "test-org")
			t.Setenv("DMG_API_ENDPOINT", server.URL)
			t.Setenv("DMG_API_KEY", "test-key")
			pidPath := filepath.Join(dir, "scan.pid")
			t.Setenv("DMG_TEST_SCAN_PID", pidPath)
			binary := filepath.Join(dir, "scan")
			if err := os.WriteFile(binary, []byte("#!/bin/sh\necho $$ > \"$DMG_TEST_SCAN_PID\"\nexec sleep 300\n"), 0700); err != nil {
				t.Fatal(err)
			}
			r := runtime{dir: dir, binary: binary, client: server.Client()}
			if err := r.setup(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- r.run() }()
			var pid int
			waitForShutdownCondition(t, func() bool {
				pidBytes, err := os.ReadFile(pidPath)
				if err != nil {
					return false
				}
				pid, err = strconv.Atoi(strings.TrimSpace(string(pidBytes)))
				return err == nil && pid > 0
			})
			stop, err := net.Dial("unix", r.socketPath())
			if err != nil {
				t.Fatal(err)
			}
			defer stop.Close()
			if _, err := fmt.Fprintln(stop, "stop"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-stopReceived:
			case <-time.After(5 * time.Second):
				t.Fatal("stop did not cancel the scan")
			}
			if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
				t.Errorf("scan still alive after stop: %v", err)
			}
			idle, err := net.Dial("unix", r.socketPath())
			if err != nil {
				t.Fatal(err)
			}
			defer idle.Close()
			// Observe the blocked reader rather than assuming the connection was accepted.
			waitForShutdownCondition(t, func() bool {
				stacks := make([]byte, 1<<20)
				n := goruntime.Stack(stacks, true)
				return strings.Contains(string(stacks[:n]), "fmt.Fscanln")
			})
			close(releaseStop)
			select {
			case err := <-done:
				if (err != nil) != failStop {
					t.Fatalf("run error = %v, want error %t", err, failStop)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("runtime did not finish")
			}
			if err := idle.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if _, err := idle.Read(b[:]); !errors.Is(err, io.EOF) {
				t.Errorf("idle client remains open after runtime exit: %v", err)
			}
			lock, err := r.acquire("runtime.lock")
			if err != nil {
				t.Fatal("runtime lock was not released:", err)
			}
			_ = lock.Close()
		})
	}
}

func waitForShutdownCondition(t *testing.T, ready func() bool) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for !ready() {
		select {
		case <-timer.C:
			t.Fatal("timed out waiting for runtime")
		case <-tick.C:
		}
	}
}
