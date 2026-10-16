package retire

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

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

	err := Post(context.Background(), srv.URL+"/", "tkey", "acme", "avd-host-07/jdoe", "1.2.3", "windows")
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
	if got.Body["agent_version"] != "1.2.3" || got.Body["platform"] != "windows" || got.Body["reason"] != Reason {
		t.Fatalf("body = %+v", got.Body)
	}
}

func TestPost_404IsNotSupported(t *testing.T) {
	var hits atomic.Int32
	srv := retireServer(t, http.StatusNotFound, &hits, nil)
	err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux")
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
	err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux")
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
	if err := Post(context.Background(), srv.URL, "k", "acme", "dev", "v", "linux"); err == nil {
		t.Fatal("expected error")
	}
	if hits.Load() != 1 {
		t.Fatalf("403 must not retry, hits = %d", hits.Load())
	}
}

func TestPost_RejectsUnusableInputs(t *testing.T) {
	if err := Post(context.Background(), "", "k", "acme", "dev", "v", "linux"); err == nil {
		t.Fatal("empty endpoint accepted")
	}
	if err := Post(context.Background(), "http://127.0.0.1:1", "k", "acme", "unknown", "v", "linux"); err == nil {
		t.Fatal("unknown device id accepted")
	}
}

func TestCollectIdentitiesIgnoresCachedAndEnvironmentIDs(t *testing.T) {
	home := t.TempDir()
	paths.SetOverride(home)
	device.ResetIDCache()
	t.Cleanup(func() { paths.SetOverride(""); device.ResetIDCache() })
	for _, path := range []string{filepath.Join(home, heartbeat.Filename), filepath.Join(home, "users", "test-user", heartbeat.Filename)} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := heartbeat.UpdateRunGate(path, func(rg *heartbeat.RunGate) { rg.DeviceID = "another-device" }); err != nil {
			t.Fatal(err)
		}
	}
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("HOST-1"))
	mock.SetEnv("STEPSEC_DEVICE_ID", "arbitrary-id")
	ids := CollectIdentities(context.Background(), mock, progress.NewNoop())
	if len(ids) != 1 || ids[0] != "HOST-1" {
		t.Fatalf("retire identities = %v, want only HOST-1", ids)
	}
}

func TestCollectIdentitiesCanceledProbeDoesNotRetireCachedID(t *testing.T) {
	device.ResetIDCache()
	t.Cleanup(device.ResetIDCache)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mock := executor.NewMock()
	mock.SetGOOS("linux")
	if ids := CollectIdentities(ctx, mock, progress.NewNoop()); len(ids) != 0 {
		t.Fatalf("unresolved identity must not retire: %v", ids)
	}
}
