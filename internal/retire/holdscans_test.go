package retire

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// testLockTarget is a lock target valid on the host OS: a file for flock, a
// mutex name on Windows (a path is not a valid kernel object name there).
func testLockTarget(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("StepSecurityDMGRetireTest-%d", time.Now().UnixNano())
	}
	return filepath.Join(t.TempDir(), "instance.flock")
}

func TestHoldScans_HoldsIdleHostAndGivesUpWhileAScanRuns(t *testing.T) {
	t.Cleanup(lock.SetTargetForTest(testLockTarget(t)))
	orig := scanHoldPoll
	scanHoldPoll = time.Millisecond
	t.Cleanup(func() { scanHoldPoll = orig })
	log := progress.NewNoop()

	release, idle := holdScans(context.Background(), []string{"dev1"}, log)
	if !idle {
		t.Fatal("idle host reported as scanning")
	}
	if _, err := lock.AcquireAll([]string{"dev1"}); !errors.Is(err, lock.ErrHeld) {
		t.Errorf("locks are not held while the retire runs: err=%v", err)
	}
	release()

	scan, err := lock.AcquireSibling("dev1") // dev1's scan is mid-flight
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, idle := holdScans(ctx, []string{"dev1"}, log); idle {
		t.Fatal("reported idle while dev1's scan held its lock")
	}
	scan.Release()

	release, idle = holdScans(context.Background(), []string{"dev1"}, log)
	if !idle {
		t.Fatal("host still reported as scanning after the scan released its lock")
	}
	release()
}

func TestStateScopes_ListsPerUserStateDirs(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	for _, d := range []string{"dev2-aaaaaaaaaaaa", "dev1-bbbbbbbbbbbb"} {
		if err := os.MkdirAll(filepath.Join(root, "users", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "users", "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(stateScopes(), ",")
	if !strings.Contains(got, "dev1-bbbbbbbbbbbb") || !strings.Contains(got, "dev2-aaaaaaaaaaaa") || strings.Contains(got, "stray") {
		t.Errorf("stateScopes() = %q, want the two user dirs and no files", got)
	}
}
