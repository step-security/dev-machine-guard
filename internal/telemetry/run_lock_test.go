package telemetry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// A run refused by the instance lock must still report a device_id: the
// backend rejects an empty one, which made lock contention invisible.
func TestRun_LockHeldReportsDeviceID(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []runStatusBody
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b runStatusBody
		_ = json.NewDecoder(r.Body).Decode(&b)
		mu.Lock()
		bodies = append(bodies, b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer withEnterpriseConfig(t, srv.URL)()
	t.Setenv(paths.HomeEnvVar, t.TempDir())

	// Hold a private instance lock so a real agent on this machine is unaffected.
	target := filepath.Join(t.TempDir(), "test.flock")
	if runtime.GOOS == "windows" {
		target = fmt.Sprintf("dmg-lock-test-%d", os.Getpid())
	}
	defer lock.SetTargetForTest(target)()
	lk, err := lock.Acquire(nil)
	if err != nil {
		t.Fatalf("taking test lock: %v", err)
	}
	defer lk.Release()

	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("SER-TEST-123\n"))

	err = Run(mock, progress.NewLogger(progress.LevelInfo), &cli.Config{})
	if err == nil {
		t.Fatal("Run succeeded while the lock was held")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 {
		t.Fatalf("got %d run-status posts, want 1: %+v", len(bodies), bodies)
	}
	b := bodies[0]
	if b.DeviceID != "SER-TEST-123" {
		t.Errorf("device_id = %q, want SER-TEST-123", b.DeviceID)
	}
	if b.Status != runStatusFailed {
		t.Errorf("status = %q, want %q", b.Status, runStatusFailed)
	}
	if !strings.HasPrefix(b.ErrorMessage, "lock_held:") {
		t.Errorf("error_message = %q, want lock_held: prefix", b.ErrorMessage)
	}
}
