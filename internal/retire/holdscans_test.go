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

	"github.com/step-security/dev-machine-guard/internal/device"
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

func TestStateScopes_ListsPerSessionStateDirs(t *testing.T) {
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
	scopes, complete := stateScopes()
	got := strings.Join(scopes, ",")
	if !complete || !strings.Contains(got, "dev1-bbbbbbbbbbbb") || !strings.Contains(got, "dev2-aaaaaaaaaaaa") || strings.Contains(got, "stray") {
		t.Errorf("stateScopes() = %q (complete %v), want the two user dirs and no files", got, complete)
	}
}

// Stray files in the users tree never hide a session directory from the
// hold: only directories count against the bound.
func TestStateScopes_StrayFilesDoNotHideASessionDirectory(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	for i := range maxScanHoldScopes + 10 {
		if err := os.WriteFile(filepath.Join(root, "users", fmt.Sprintf("a-stray-%03d.txt", i)), []byte("x"), 0o644); err != nil {
			if os.IsNotExist(err) {
				if err := os.MkdirAll(filepath.Join(root, "users"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "users", fmt.Sprintf("a-stray-%03d.txt", i)), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "users", "zz-dev9-cccccccccccc"), 0o755); err != nil {
		t.Fatal(err)
	}
	scopes, complete := stateScopes()
	if !complete || strings.Join(scopes, ",") != "zz-dev9-cccccccccccc" {
		t.Errorf("stateScopes() = %q (complete %v), want the one session directory past the stray files", scopes, complete)
	}
}

// More session directories than can be held at once (a user-creatable tree)
// means the set cannot be inspected: HoldScans reports the host as not idle
// without taking a lock.
func TestHoldScans_SkipsWhenTheScopeSetIsUnbounded(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	for i := range maxScanHoldScopes + 1 {
		if err := os.MkdirAll(filepath.Join(root, "users", fmt.Sprintf("u%03d-aaaaaaaaaaaa", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, complete := stateScopes(); complete {
		t.Fatal("stateScopes() reported a complete listing past the bound")
	}
	t.Cleanup(lock.SetTargetForTest(testLockTarget(t)))
	if _, idle := HoldScans(context.Background(), progress.NewNoop()); idle {
		t.Fatal("HoldScans reported idle without being able to inspect every scope")
	}
}

// A lock that cannot be inspected at all (here: its file cannot be created)
// is not evidence that the host is idle; the retire does not proceed.
func TestHoldScans_UninspectableLockIsNotIdle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows lock is a named mutex; there is no path to make unopenable")
	}
	t.Cleanup(lock.SetTargetForTest(filepath.Join(t.TempDir(), "missing-dir", "instance.flock")))
	orig := scanHoldPoll
	scanHoldPoll = time.Millisecond
	t.Cleanup(func() { scanHoldPoll = orig })
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, idle := holdScans(ctx, []string{"dev1"}, progress.NewNoop()); idle {
		t.Fatal("an uninspectable lock was taken as proof that no scan runs")
	}
}

// The updater's switch: a session scan holds only its own lock, and
// AcquireScans refuses while it runs; once the host is idle it holds the
// machine-wide lock and every session's, so no listed scan starts mid-switch.
func TestAcquireScans_RefusesWhileASessionScanRuns(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	for _, d := range []string{"dev1-aaaaaaaaaaaa", "dev2-bbbbbbbbbbbb"} {
		if err := os.MkdirAll(filepath.Join(root, "users", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(lock.SetTargetForTest(testLockTarget(t)))

	scan, err := lock.AcquireSibling("dev2-bbbbbbbbbbbb") // dev2's scan is mid-flight
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := AcquireScans(); !errors.Is(err, lock.ErrHeld) {
		t.Fatalf("AcquireScans while dev2's scan runs: err=%v, want ErrHeld", err)
	}
	scan.Release()

	release, complete, err := AcquireScans()
	if err != nil || !complete {
		t.Fatalf("AcquireScans on an idle host: complete=%v err=%v", complete, err)
	}
	for _, s := range []string{"dev1-aaaaaaaaaaaa", "dev2-bbbbbbbbbbbb"} {
		if _, err := lock.AcquireSibling(s); !errors.Is(err, lock.ErrHeld) {
			t.Errorf("%s's scan could start during the switch: err=%v", s, err)
		}
	}
	if _, err := lock.Acquire(nil); !errors.Is(err, lock.ErrHeld) {
		t.Errorf("a machine-wide scan could start during the switch: err=%v", err)
	}
	release()
}

// Past the listing bound the updater still switches (a user can fill the
// tree; that must not hold updates back), holding the machine-wide lock and
// the scopes listed before the bound.
func TestAcquireScans_SwitchesPastTheListingBound(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	for i := range maxScanHoldScopes + 1 {
		if err := os.MkdirAll(filepath.Join(root, "users", fmt.Sprintf("u%03d-aaaaaaaaaaaa", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(lock.SetTargetForTest(testLockTarget(t)))
	release, complete, err := AcquireScans()
	if err != nil || complete {
		t.Fatalf("AcquireScans past the bound: complete=%v err=%v, want a partial hold", complete, err)
	}
	if _, err := lock.Acquire(nil); !errors.Is(err, lock.ErrHeld) {
		t.Errorf("machine-wide lock not held: err=%v", err)
	}
	held := 0
	for i := range maxScanHoldScopes + 1 {
		lk, err := lock.AcquireSibling(fmt.Sprintf("u%03d-aaaaaaaaaaaa", i))
		if errors.Is(err, lock.ErrHeld) {
			held++
		} else if err == nil {
			lk.Release()
		}
	}
	if held != maxScanHoldScopes {
		t.Errorf("%d session locks held, want the %d listed before the bound", held, maxScanHoldScopes)
	}
	release()
}

// Past the entry bound the directories already read are kept: the listing
// is incomplete, not empty.
func TestStateScopes_KeepsTheScopesReadBeforeTheEntryBound(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	users := filepath.Join(root, "users")
	if err := os.MkdirAll(users, 0o755); err != nil {
		t.Fatal(err)
	}
	const dirs = 10
	for i := range dirs {
		if err := os.Mkdir(filepath.Join(users, fmt.Sprintf("dev%d-aaaaaaaaaaaa", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	extra := 4
	for i := range maxUsersDirEntries - dirs + extra {
		if err := os.WriteFile(filepath.Join(users, fmt.Sprintf("stray%05d", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scopes, complete := stateScopes()
	if complete {
		t.Fatal("stateScopes() reported a complete listing past the entry bound")
	}
	if len(scopes) < dirs-extra {
		t.Errorf("stateScopes() kept %d scopes, want at least the %d read before the bound", len(scopes), dirs-extra)
	}
}

// A directory name longer than any user token is no session's scope: it is
// skipped, so a planted one cannot make the updater's locks fail (its mutex
// name would exceed the Windows limit) and hold the switch back.
func TestAcquireScans_SkipsANameNoSessionCanHave(t *testing.T) {
	root := t.TempDir()
	t.Setenv(paths.HomeEnvVar, root)
	planted := strings.Repeat("x", device.MaxUserTokenLen+1)
	for _, d := range []string{planted, "dev1-aaaaaaaaaaaa"} {
		if err := os.MkdirAll(filepath.Join(root, "users", d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	scopes, complete := stateScopes()
	if !complete || len(scopes) != 1 || scopes[0] != "dev1-aaaaaaaaaaaa" {
		t.Fatalf("stateScopes() = %q (complete %v), want only the session scope", scopes, complete)
	}
	t.Cleanup(lock.SetTargetForTest(testLockTarget(t)))
	release, _, err := AcquireScans()
	if err != nil {
		t.Fatalf("AcquireScans with a planted name: %v", err)
	}
	release()
}
