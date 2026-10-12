package updateinstall

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
}
func assertPair(t *testing.T, dir, prefix string) {
	t.Helper()
	for _, name := range []string{Launcher, Agent} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(b) != prefix+name {
			t.Fatalf("%s = %q, %v", name, b, err)
		}
	}
}
func pairFixture(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{Launcher, Agent} {
		writeFixture(t, filepath.Join(dir, n), "old-"+n)
		writeFixture(t, filepath.Join(dir, "new-"+n), "new-"+n)
	}
	return dir, filepath.Join(dir, "new-"+Launcher), filepath.Join(dir, "new-"+Agent)
}
func TestReplacePair_CommitAndSecondFileFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			dir, l, a := pairFixture(t)
			lock, err := Acquire(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Release()
			if fail {
				a = filepath.Join(dir, "missing")
			}
			err = ReplacePair(dir, l, a)
			if fail {
				if err == nil {
					t.Fatal("expected failure")
				}
				assertPair(t, dir, "old-")
			} else {
				if err != nil {
					t.Fatal(err)
				}
				assertPair(t, dir, "new-")
			}
			if err = Recover(dir); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(dir, journalName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("pending journal after recovery")
			}
		})
	}
}

func TestCrashHelper(t *testing.T) {
	if os.Getenv("DMG_TEST_CRASH") != "1" {
		return
	}
	dir := os.Getenv("DMG_TEST_DIR")
	lk, err := Acquire(dir)
	if err != nil {
		os.Exit(90)
	}
	defer lk.Release()
	err = replacePair(dir, filepath.Join(dir, "new-"+Launcher), filepath.Join(dir, "new-"+Agent), func(phase string) {
		if phase == os.Getenv("DMG_TEST_PHASE") {
			os.Exit(37)
		}
	})
	if err != nil {
		os.Exit(91)
	}
	os.Exit(92)
}
func TestRecover_AfterProcessDeathAtEveryReplacementBoundary(t *testing.T) {
	for _, phase := range []string{"journal", "aside:" + Launcher, "installed:" + Launcher, "aside:" + Agent, "installed:" + Agent} {
		t.Run(phase, func(t *testing.T) {
			dir, _, _ := pairFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCrashHelper$")
			cmd.Env = append(os.Environ(), "DMG_TEST_CRASH=1", "DMG_TEST_DIR="+dir, "DMG_TEST_PHASE="+phase)
			err := cmd.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 37 {
				t.Fatalf("crash helper: %v", err)
			}
			lk, err := Acquire(dir)
			if err != nil {
				t.Fatalf("lock not released on process death: %v", err)
			}
			defer lk.Release()
			if err = Recover(dir); err != nil {
				t.Fatal(err)
			}
			assertPair(t, dir, "old-")
			if err = Recover(dir); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestImageHelper(t *testing.T) {
	if os.Getenv("DMG_TEST_IMAGE") != "1" {
		return
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}
func holdImage(t *testing.T, path string) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, path, "-test.run=^TestImageHelper$")
	cmd.Env = append(os.Environ(), "DMG_TEST_IMAGE=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	reader := bufio.NewReader(out)
	line, err := reader.ReadString('\n')
	if err != nil || line != "ready\n" {
		cancel()
		t.Fatalf("image startup: %q, %v", line, err)
	}
	return func() {
		_ = in.Close()
		if err := cmd.Wait(); err != nil {
			t.Errorf("image exit: %v", err)
		}
		cancel()
	}
}
func TestReplacePair_LiveExecutableImages(t *testing.T) {
	dir := t.TempDir()
	me, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{Launcher, Agent} {
		if _, err = copySynced(me, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if _, err = copySynced(me, filepath.Join(dir, "new-"+name)); err != nil {
			t.Fatal(err)
		}
	}
	stopLauncher := holdImage(t, filepath.Join(dir, Launcher))
	defer stopLauncher()
	stopAgent := holdImage(t, filepath.Join(dir, Agent))
	defer stopAgent()
	lk, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	if err = ReplacePair(dir, filepath.Join(dir, "new-"+Launcher), filepath.Join(dir, "new-"+Agent)); err != nil {
		t.Fatal(err)
	}
	// Both replacements must actually launch, while both original images remain mapped.
	stopNewLauncher := holdImage(t, filepath.Join(dir, Launcher))
	stopNewLauncher()
	stopNewAgent := holdImage(t, filepath.Join(dir, Agent))
	stopNewAgent()
}
func TestAcquire_ExcludesConcurrentUpdater(t *testing.T) {
	dir := t.TempDir()
	first, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Acquire(dir)
	if err == nil {
		second.Release()
		first.Release()
		t.Fatal("second lock succeeded")
	}
	first.Release()
	third, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	third.Release()
}

func TestRecover_RejectsCorruptBackupBeforeChangingEitherImage(t *testing.T) {
	dir, l, a := pairFixture(t)
	lk, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	// Leave a real journal and partial replacement, then corrupt the second
	// backup. Recovery must validate the complete pair before touching either.
	err = replacePair(dir, l, a, func(phase string) {
		if phase == "installed:"+Launcher {
			matches, globErr := filepath.Glob(filepath.Join(dir, backupPrefix+"*", Agent))
			if globErr != nil || len(matches) != 1 {
				t.Fatalf("find backup: %v, %v", matches, globErr)
			}
			writeFixture(t, matches[0], "corrupt")
			if removeErr := os.Remove(a); removeErr != nil {
				t.Fatal(removeErr)
			}
		}
	})
	if err == nil {
		t.Fatal("expected failed install and failed rollback")
	}
	got, err := os.ReadFile(filepath.Join(dir, Launcher))
	if err != nil || string(got) != "new-"+Launcher {
		t.Fatalf("recovery changed launcher before validating both backups: %q, %v", got, err)
	}
	if _, err = os.Stat(filepath.Join(dir, journalName)); err != nil {
		t.Fatal("failed recovery must preserve the journal")
	}
	if err = Recover(dir); err == nil {
		t.Fatal("corrupt backup accepted on retry")
	}
}

func TestLockContenderHelper(t *testing.T) {
	if os.Getenv("DMG_TEST_CONTENDER") != "1" {
		return
	}
	lk, err := Acquire(os.Getenv("DMG_TEST_DIR"))
	if err != nil {
		os.Exit(38)
	}
	lk.Release()
	os.Exit(0)
}

func TestAcquire_ExcludesAnotherProcess(t *testing.T) {
	dir := t.TempDir()
	lk, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLockContenderHelper$")
	cmd.Env = append(os.Environ(), "DMG_TEST_CONTENDER=1", "DMG_TEST_DIR="+dir)
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 38 {
		t.Fatalf("another process acquired the installation lock: %v", err)
	}
}
