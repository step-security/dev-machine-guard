package retire

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
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

	err := Post(context.Background(), srv.URL+"/", "tkey", "acme", "avd-host-07/jdoe", "1.2.3", "windows", ReasonUninstall)
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

func TestPost_404IsNotSupported(t *testing.T) {
	var hits atomic.Int32
	srv := retireServer(t, http.StatusNotFound, &hits, nil)
	err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux", ReasonUninstall)
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
	err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux", ReasonUninstall)
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
	if err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux", ReasonUninstall); err == nil {
		t.Fatal("expected error")
	}
	if hits.Load() != 1 {
		t.Fatalf("403 must not retry, hits = %d", hits.Load())
	}
}

func TestPost_RejectsUnusableInputs(t *testing.T) {
	if err := Post(context.Background(), "", "k", "acme", "dev", "v", "linux", ReasonUninstall); err == nil {
		t.Fatal("empty endpoint accepted")
	}
	if err := Post(context.Background(), "http://127.0.0.1:1", "k", "acme", "unknown", "v", "linux", ReasonUninstall); err == nil {
		t.Fatal("unknown device id accepted")
	}
}

// seedState writes a last-run.json carrying a run-gate device id at path.
func seedState(t *testing.T, path, deviceID string) {
	t.Helper()
	if err := heartbeat.UpdateRunGate(path, func(rg *heartbeat.RunGate) { rg.DeviceID = deviceID }); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

func TestCollectIdentities_FromUserStateDirs(t *testing.T) {
	home := t.TempDir()
	paths.SetOverride(home)
	t.Cleanup(func() { paths.SetOverride("") })
	prev := config.DeviceID
	config.DeviceID = "{hostname}-{user}"
	t.Cleanup(func() { config.DeviceID = prev })

	// The MSI uninstall runs as SYSTEM: the template cannot be completed, so
	// only the cached per-user ids can be retired.
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
	want := []string{"avd-host-07-admin", "avd-host-07-asmith", "avd-host-07-jdoe"}
	if len(ids) != len(want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ids = %v, want %v", ids, want)
		}
	}

	// As a real user the resolved identity comes first, then the cache.
	mock.SetUsername(`CONTOSO\JDoe`)
	ids = CollectIdentities(context.Background(), mock, progress.NewNoop())
	if len(ids) != 3 || ids[0] != "avd-host-07-jdoe" {
		t.Fatalf("resolved id must lead: %v", ids)
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
	got := collectCachedIDs([]string{empty, machine})
	want := []string{"host-dev1", "host-dev2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("collectCachedIDs = %v, want %v", got, want)
	}
	if got := collectCachedIDs([]string{""}); len(got) != 0 {
		t.Fatalf("empty root must yield nothing, got %v", got)
	}
}
