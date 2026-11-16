package retire

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

type capturedRequest struct {
	Path   string
	Bearer string
	Body   map[string]string
}

func retireServer(t *testing.T, status int, hits *atomic.Int32, captured *capturedRequest) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if captured != nil {
			captured.Path = r.URL.EscapedPath()
			captured.Bearer = r.Header.Get("Authorization")
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &captured.Body)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"status":"retired"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPost_PathBearerBody(t *testing.T) {
	var hits atomic.Int32
	var got capturedRequest
	srv := retireServer(t, http.StatusOK, &hits, &got)

	_, err := Post(context.Background(), srv.URL+"/", "tkey", "acme", "avd-host-07/jdoe", "1.2.3", "windows", ReasonUninstall)
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", hits.Load())
	}
	if got.Path != "/v1/acme/developer-mdm-agent/devices/avd-host-07%2Fjdoe/retire" {
		t.Fatalf("path = %q", got.Path)
	}
	if got.Bearer != "Bearer tkey" {
		t.Fatalf("bearer = %q", got.Bearer)
	}
	if got.Body["agent_version"] != "1.2.3" || got.Body["platform"] != "windows" || got.Body["reason"] != ReasonUninstall {
		t.Fatalf("body = %+v", got.Body)
	}
}

func TestPost_ReturnsBackendStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"device_id":"laptop-1","status":"out_of_scope","already_retired":false}`))
	}))
	t.Cleanup(srv.Close)
	status, err := Post(context.Background(), srv.URL, "k", "acme", "laptop-1", "v", "windows", ReasonUninstall)
	if err != nil || status != StatusOutOfScope {
		t.Fatalf("status=%q err=%v, want %q", status, err, StatusOutOfScope)
	}
	// A 2xx without a status body is still a success.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(plain.Close)
	if status, err := Post(context.Background(), plain.URL, "k", "acme", "laptop-1", "v", "windows", ReasonUninstall); err != nil || status != "" {
		t.Fatalf("plain 2xx: status=%q err=%v", status, err)
	}
}

func TestPost_404IsNotSupported(t *testing.T) {
	var hits atomic.Int32
	srv := retireServer(t, http.StatusNotFound, &hits, nil)
	_, err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux", ReasonUninstall)
	if err == nil || err != ErrNotSupported {
		t.Fatalf("err = %v, want ErrNotSupported", err)
	}
	if hits.Load() != 1 {
		t.Fatalf("404 must be terminal, hits = %d", hits.Load())
	}
}

func TestPost_RetriesOn5xxThenGivesUp(t *testing.T) {
	var hits atomic.Int32
	srv := retireServer(t, http.StatusBadGateway, &hits, nil)
	start := time.Now()
	_, err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux", ReasonUninstall)
	if err == nil {
		t.Fatal("expected an error after exhausting attempts")
	}
	if hits.Load() != int32(attempts) {
		t.Fatalf("hits = %d, want %d", hits.Load(), attempts)
	}
	if time.Since(start) > TotalBudget {
		t.Fatalf("retire exceeded its budget: %s", time.Since(start))
	}
}

func TestPost_4xxIsTerminal(t *testing.T) {
	var hits atomic.Int32
	srv := retireServer(t, http.StatusForbidden, &hits, nil)
	if _, err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux", ReasonUninstall); err == nil {
		t.Fatal("expected error")
	}
	if hits.Load() != 1 {
		t.Fatalf("403 must not retry, hits = %d", hits.Load())
	}
}

func TestPost_RejectsUnusableInputs(t *testing.T) {
	if _, err := Post(context.Background(), "", "k", "acme", "dev", "v", "linux", ReasonUninstall); err == nil {
		t.Fatal("empty endpoint accepted")
	}
	if _, err := Post(context.Background(), "http://127.0.0.1:1", "k", "acme", "unknown", "v", "linux", ReasonUninstall); err == nil {
		t.Fatal("unknown device id accepted")
	}
}

// seedState writes a last-run.json carrying a run-gate device id at path.
func seedState(t *testing.T, path, deviceID string) {
	t.Helper()
	seedStateFrom(t, path, deviceID, "")
}

// seedStateFrom seeds a run-gate record that names the machine it was
// recorded on ("" for a record an older agent wrote).
func seedStateFrom(t *testing.T, path, deviceID, machineID string) {
	t.Helper()
	if err := heartbeat.UpdateRunGate(path, func(rg *heartbeat.RunGate) { rg.DeviceID = deviceID; rg.MachineID = machineID }); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

// A host cloned from an image carries the builder's state tree. Its
// uninstall retires this machine's devices and the records of older agents,
// never a device another machine recorded.
func TestCollectIdentities_SkipsRecordsOfAnotherMachine(t *testing.T) {
	home := t.TempDir()
	paths.SetOverride(home)
	t.Cleanup(func() { paths.SetOverride("") })
	prev := config.DeviceID
	config.DeviceID = "{hostname}"
	t.Cleanup(func() { config.DeviceID = prev })
	device.ResetIDCache()
	t.Cleanup(device.ResetIDCache)

	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetHostname("avd-07")
	mock.SetUsername("jdoe")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("LNX-CLONE\n"))

	seed := func(user, id, machine string) {
		dir := filepath.Join(home, "users", user)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		seedStateFrom(t, filepath.Join(dir, heartbeat.Filename), id, machine)
	}
	seed("builder", "avd-builder-admin", "LNX-BUILDER") // captured into the image
	seed("asmith", "avd-07-asmith", "LNX-CLONE")        // scanned on this clone
	seed("legacy", "avd-07-legacy", "")                 // an older agent's record

	ids := CollectIdentities(context.Background(), mock, progress.NewNoop())
	// The machine identity leads; the cached records of this machine (an
	// older build's per-user ids among them) follow; the builder's does not.
	want := []string{"avd-07", "avd-07-asmith", "avd-07-legacy"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
}

func TestCollectIdentities_FromUserStateDirs(t *testing.T) {
	home := t.TempDir()
	paths.SetOverride(home)
	t.Cleanup(func() { paths.SetOverride("") })
	prev := config.DeviceID
	config.DeviceID = "{hostname}"
	t.Cleanup(func() { config.DeviceID = prev })

	// The MSI uninstall runs as SYSTEM: the identity is the machine's either
	// way, and every cached record this machine wrote (an older build's
	// per-user ids included) is retired with it.
	device.ResetIDCache()
	t.Cleanup(device.ResetIDCache)
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHostname("avd-host-07")
	mock.SetUsername(`NT AUTHORITY\SYSTEM`)

	seedState(t, filepath.Join(home, heartbeat.Filename), "avd-host-07-admin")
	for _, u := range []string{"jdoe", "asmith", "jdoe-dup"} {
		dir := filepath.Join(home, "users", u)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		id := "avd-host-07-" + u
		if u == "jdoe-dup" {
			id = "avd-host-07-jdoe" // duplicate id across two state dirs
		}
		seedState(t, filepath.Join(dir, heartbeat.Filename), id)
	}
	// A corrupt state file is skipped, not fatal.
	if err := os.MkdirAll(filepath.Join(home, "users", "broken"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "users", "broken", heartbeat.Filename), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	ids := CollectIdentities(context.Background(), mock, progress.NewNoop())
	want := []string{"avd-host-07", "avd-host-07-admin", "avd-host-07-asmith", "avd-host-07-jdoe"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("ids = %v, want %v", ids, want)
	}

	// A signed-in user resolves the same machine identity.
	mock.SetUsername(`CONTOSO\JDoe`)
	ids = CollectIdentities(context.Background(), mock, progress.NewNoop())
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
}

func TestCollectIdentities_DefaultSerialWithNoState(t *testing.T) {
	paths.SetOverride(t.TempDir())
	t.Cleanup(func() { paths.SetOverride("") })
	prev := config.DeviceID
	config.DeviceID = ""
	t.Cleanup(func() { config.DeviceID = prev })

	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("LNX-1\n"))
	ids := CollectIdentities(context.Background(), mock, progress.NewNoop())
	if len(ids) != 1 || ids[0] != "LNX-1" {
		t.Fatalf("ids = %v", ids)
	}
}

func TestCollectCachedIDs_SearchesEveryRoot(t *testing.T) {
	// An MSI uninstall runs as SYSTEM: its own home has no state, the
	// machine-wide dir holds the per-user caches. Both roots are searched and
	// the order is stable.
	empty := t.TempDir()
	machine := t.TempDir()
	for _, u := range []string{"dev2", "dev1"} {
		dir := filepath.Join(machine, "users", u)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, heartbeat.Filename),
			[]byte(`{"schema_version":1,"run_gate":{"device_id":"host-`+u+`"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := collectCachedIDs(context.Background(), []string{empty, machine}, "", progress.NewNoop())
	want := []string{"host-dev1", "host-dev2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("collectCachedIDs = %v, want %v", got, want)
	}
	if got := collectCachedIDs(context.Background(), []string{""}, "", progress.NewNoop()); len(got) != 0 {
		t.Fatalf("empty root must yield nothing, got %v", got)
	}
}

// Identity collection is bounded: an oversized state file is skipped without
// being read, and a cancelled budget stops the walk.
func TestCollectCachedIDs_BoundsFilesAndBudget(t *testing.T) {
	root := t.TempDir()
	put := func(user, body string) {
		t.Helper()
		dir := filepath.Join(root, "users", user)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, heartbeat.Filename), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	put("big", `{"schema_version":1,"run_gate":{"device_id":"host-big","pad":"`+strings.Repeat("x", maxCachedIDFileBytes)+`"}}`)
	put("ok", `{"schema_version":1,"run_gate":{"device_id":"host-ok"}}`)
	if got := collectCachedIDs(context.Background(), []string{root}, "", progress.NewNoop()); strings.Join(got, ",") != "host-ok" {
		t.Fatalf("collectCachedIDs = %v, want [host-ok] (oversized file skipped)", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := collectCachedIDs(ctx, []string{root}, "", progress.NewNoop()); len(got) != 0 {
		t.Fatalf("a spent budget must stop the collection, got %v", got)
	}
}

// The retire budget grows with the number of identities (one attempt plus
// its retry each) and is capped so a host with many per-user rows still
// uninstalls promptly.
func TestBudgetFor(t *testing.T) {
	if got := BudgetFor(0); got != TotalBudget {
		t.Errorf("BudgetFor(0) = %v, want %v", got, TotalBudget)
	}
	if got := BudgetFor(1); got != TotalBudget {
		t.Errorf("BudgetFor(1) = %v, want %v", got, TotalBudget)
	}
	if got, want := BudgetFor(5), TotalBudget+4*perIdentityBudget; got != want {
		t.Errorf("BudgetFor(5) = %v, want %v", got, want)
	}
	if got := BudgetFor(MaxIdentities); got != MaxBudget {
		t.Errorf("BudgetFor(%d) = %v, want the cap %v", MaxIdentities, got, MaxBudget)
	}
}

// A shared host at the identity cap (one root, many users) has every per-user
// cache read: the file cap covers MaxIdentities caches plus the top-level
// heartbeat.
func TestCollectIdentities_ManyUsersInOneRoot(t *testing.T) {
	home := t.TempDir()
	paths.SetOverride(home)
	t.Cleanup(func() { paths.SetOverride("") })
	prev := config.DeviceID
	config.DeviceID = "{hostname}"
	t.Cleanup(func() { config.DeviceID = prev })
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHostname("avd-host-07")
	mock.SetUsername(`NT AUTHORITY\SYSTEM`)
	if err := os.WriteFile(filepath.Join(home, heartbeat.Filename), []byte(`{"schema_version":1,"run_gate":{"device_id":"SER-1"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	const users = 70
	for i := 0; i < users; i++ {
		dir := filepath.Join(home, "users", "u"+strconv.Itoa(i))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, heartbeat.Filename), []byte(`{"schema_version":1,"run_gate":{"device_id":"host-u`+strconv.Itoa(i)+`"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ids := CollectIdentities(context.Background(), mock, progress.NewNoop())
	// The resolved machine identity, the machine row's cached id (written by
	// an older build under the serial) and every per-session record.
	if len(ids) != users+2 {
		t.Fatalf("collected %d ids, want %d (resolved id, machine record, %d per-session records)", len(ids), users+2, users)
	}
}
