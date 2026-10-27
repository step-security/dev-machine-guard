//go:build selfupdate_faults

package telemetry

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/updatestate"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

// FR1-2: a real panic in the scan, before or after run-status "started",
// is recovered by Run but must end the process as a crash (exit 2), so the
// run record classifies Bad, never Healthy or Neutral.
func TestScanPanicIsABadRun(t *testing.T) {
	for _, cp := range []string{"scan.before-started", "scan.after-started"} {
		t.Run(cp, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			defer srv.Close()
			defer withEnterpriseConfig(t, srv.URL)()
			t.Setenv(paths.HomeEnvVar, t.TempDir())
			target := filepath.Join(t.TempDir(), "test.flock")
			if runtime.GOOS == "windows" {
				target = fmt.Sprintf("dmg-panic-test-%d-%d", os.Getpid(), time.Now().UnixNano())
			}
			defer lock.SetTargetForTest(target)()

			runs := filepath.Join(t.TempDir(), "runs", "1.20.0.json")
			if err := updatestate.AppendRun(runs, updatestate.RunRecord{RunID: "r1", Version: "1.20.0"}); err != nil {
				t.Fatal(err)
			}
			t.Setenv(EnvRunRecord, runs)
			t.Setenv(EnvRunID, "r1")
			t.Setenv("DMG_FAULT", cp+":panic")

			mock := executor.NewMock()
			mock.SetGOOS(model.PlatformLinux)
			mock.SetFile("/sys/class/dmi/id/product_serial", []byte("SER-TEST-123\n"))
			err := Run(mock, progress.NewLogger(progress.LevelError), &cli.Config{SearchDirs: []string{t.TempDir()}})
			if !errors.Is(err, ErrPanic) {
				t.Fatalf("Run = %v, want ErrPanic", err)
			}
			code := ExitCode(err)
			if err := updatestate.FinalizeRun(runs, "r1", code, false, time.Now()); err != nil {
				t.Fatal(err)
			}
			rec := updatestate.ReadRuns(runs)[0]
			if v := updatestate.ClassifyRun(rec); v != updatestate.RunBad {
				t.Fatalf("panic %s: exit %d, started=%v → verdict %v, want Bad", cp, code, rec.Started, v)
			}
		})
	}
}

// envHangScan names the env var that turns TestHelperHangScan into the
// hanging scan subprocess; its value is the fake backend URL.
const envHangScan = "DMG_TEST_HANG_SCAN"

// TestHelperHangScan is a subprocess body: a real scan that blocks forever
// at scan.after-started. It does nothing in a normal test run.
func TestHelperHangScan(t *testing.T) {
	endpoint := os.Getenv(envHangScan)
	if endpoint == "" {
		t.Skip("subprocess helper")
	}
	proctest.Guard()
	defer withEnterpriseConfig(t, endpoint)()
	defer lock.SetTargetForTest(os.Getenv(envHangScan + "_LOCK"))()
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformLinux)
	mock.SetFile("/sys/class/dmi/id/product_serial", []byte("SER-TEST-123\n"))
	_ = Run(mock, progress.NewLogger(progress.LevelError), &cli.Config{SearchDirs: []string{t.TempDir()}})
	os.Exit(3) // never reached: the scan hangs until killed
}

// FR1-7: a real hang after run-status "started" (the scan blocks forever at
// scan.after-started) is ended by the bootstrap's watchdog and must count
// Bad, not Healthy. The hung scan runs in a subprocess that the "watchdog"
// kills and reaps, so nothing of it lives on in the test process.
func TestScanHangAfterStartedIsABadRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer srv.Close()
	target := filepath.Join(t.TempDir(), "test.flock")
	if runtime.GOOS == "windows" {
		target = fmt.Sprintf("dmg-hang-test-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	runs := filepath.Join(t.TempDir(), "runs", "1.20.0.json")
	if err := updatestate.AppendRun(runs, updatestate.RunRecord{RunID: "h1", Version: "1.20.0"}); err != nil {
		t.Fatal(err)
	}
	cmd := proctest.Command(t, os.Args[0], "-test.run=^TestHelperHangScan$")
	cmd.Env = append(cmd.Env,
		envHangScan+"="+srv.URL, envHangScan+"_LOCK="+target,
		paths.HomeEnvVar+"="+t.TempDir(),
		EnvRunRecord+"="+runs, EnvRunID+"=h1",
		"DMG_FAULT=scan.after-started:hang",
		"GORACE=atexit_sleep_ms=0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	reap := func() {
		if !reaped {
			reaped = true
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}
	defer reap() // before the fixtures' own cleanup
	deadline := time.Now().Add(60 * time.Second)
	for !updatestate.ReadRuns(runs)[0].Started {
		if time.Now().After(deadline) {
			t.Fatal("the scan never posted started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The bootstrap's watchdog fires: it kills the scan, exit 124,
	// watchdog_killed.
	reap()
	if err := updatestate.FinalizeRun(runs, "h1", 124, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v := updatestate.ClassifyRun(updatestate.ReadRuns(runs)[0]); v != updatestate.RunBad {
		t.Fatalf("hang after started: verdict %v, want Bad", v)
	}
	// Copilot 4356483353: the hung scan must not live on in the test
	// process holding the scan lock.
	defer lock.SetTargetForTest(target)()
	l, err := lock.Acquire(nil)
	if err != nil {
		t.Fatalf("the hung scan still holds the scan lock: %v", err)
	}
	l.Release()
}
