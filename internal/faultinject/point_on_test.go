//go:build selfupdate_faults

package faultinject

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/proctest"
)

func stubExit(t *testing.T) *int {
	t.Helper()
	code := -1
	old := exit
	exit = func(c int) { code = c }
	t.Cleanup(func() { exit = old })
	return &code
}

func stubSystem(t *testing.T, system bool) {
	t.Helper()
	old := isSystem
	isSystem = func() bool { return system }
	t.Cleanup(func() { isSystem = old })
}

func TestPointActions(t *testing.T) {
	t.Setenv("DMG_FAULT", "S0.locked:err, S4.downloaded:agent.exe:diskfull,S5.smoked:exit3,S1.swept:kill,S2.evaluated:exit2")
	if !Enabled {
		t.Fatal("Enabled = false with the tag")
	}
	if err := Point("S3.target"); err != nil {
		t.Fatalf("unconfigured checkpoint: %v", err)
	}
	if err := Point("S0.locked"); !errors.Is(err, ErrInjected) || !strings.Contains(err.Error(), "S0.locked") {
		t.Fatalf("err action = %v", err)
	}
	err := Point("S4.downloaded:agent.exe")
	if !errors.Is(err, ErrInjected) || !errors.Is(err, errDiskFull) {
		t.Fatalf("diskfull action = %v", err)
	}
	if err := Point("S4.downloaded:task.exe"); err != nil {
		t.Fatalf("other asset matched: %v", err)
	}
	for name, want := range map[string]int{"S5.smoked": 3, "S1.swept": 137, "S2.evaluated": 2} {
		code := stubExit(t)
		if err := Point(name); err != nil || *code != want {
			t.Fatalf("%s: code %d err %v, want %d", name, *code, err, want)
		}
	}
}

// R-F1-4/R-F1-7: a malformed spec fails loudly at first use with its own
// exit code and marker, never as a silent no-op and never as exit 2.
func TestPointMalformedSpecExits64(t *testing.T) {
	for _, spec := range badSpecs {
		t.Run(spec, func(t *testing.T) {
			t.Setenv("DMG_FAULT", spec)
			code := stubExit(t)
			var buf strings.Builder
			old := stderr
			stderr = &buf
			t.Cleanup(func() { stderr = old })
			if err := Point("S0.locked"); !errors.Is(err, ErrInjected) {
				t.Fatalf("Point = %v", err)
			}
			if *code != MalformedExitCode || !strings.HasPrefix(buf.String(), MalformedMarker) {
				t.Fatalf("exit %d, stderr %q", *code, buf.String())
			}
		})
	}
	old := Baked
	t.Cleanup(func() { Baked = old })
	Baked = "S0.locked:typo"
	t.Setenv("DMG_FAULT", "")
	code := stubExit(t)
	stderr = io.Discard
	t.Cleanup(func() { stderr = os.Stderr })
	_ = Point("S0.locked")
	if *code != MalformedExitCode {
		t.Fatalf("malformed Baked: exit %d", *code)
	}
}

// A real process with a malformed spec exits 64 with the marker (not 2).
func TestMalformedSpecProcessExit(t *testing.T) {
	cmd := proctest.Command(t, os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(cmd.Env, "FAULTINJECT_HELPER=1", "FAULTINJECT_MARKER="+filepath.Join(t.TempDir(), "m"), "DMG_FAULT=S6.state-temp@sytem:kill")
	out, _ := cmd.CombinedOutput()
	if code := cmd.ProcessState.ExitCode(); code != MalformedExitCode || !strings.Contains(string(out), MalformedMarker) {
		t.Fatalf("exit %d, output %q", code, out)
	}
}

func TestPointColonCheckpoint(t *testing.T) {
	t.Setenv("DMG_FAULT", "S4.downloaded:agent.exe:err")
	if err := Point("S4.downloaded:agent.exe"); !errors.Is(err, ErrInjected) {
		t.Fatalf("Point = %v", err)
	}
	if err := Point("S4.downloaded:task.exe"); err != nil {
		t.Fatalf("other asset fired: %v", err)
	}
}

func TestPointPrincipalQualifier(t *testing.T) {
	t.Setenv("DMG_FAULT", "boot.resolved@system:err,boot.launched@user:err")
	for _, system := range []bool{false, true} {
		stubSystem(t, system)
		if got := Point("boot.resolved") != nil; got != system {
			t.Errorf("system=%v: @system fired=%v", system, got)
		}
		if got := Point("boot.launched") != nil; got == system {
			t.Errorf("system=%v: @user fired=%v", system, got)
		}
	}
}

func TestPointMergesBaked(t *testing.T) {
	old := Baked
	t.Cleanup(func() { Baked = old })
	Baked = "agent.prestart:err"
	t.Setenv("DMG_FAULT", "S7.reported:err")
	if Point("agent.prestart") == nil || Point("S7.reported") == nil {
		t.Fatal("Baked and DMG_FAULT must both apply")
	}
	t.Setenv("DMG_FAULT", "")
	if Point("agent.prestart") == nil {
		t.Fatal("Baked must apply without DMG_FAULT")
	}
}

func TestPointTrace(t *testing.T) {
	trace := filepath.Join(t.TempDir(), "trace")
	t.Setenv("DMG_FAULT_TRACE", trace)
	t.Setenv("DMG_FAULT", "S6.mutex:err")
	for _, n := range []string{"S0.locked", "S4.downloaded:agent.exe", "S6.mutex"} {
		_ = Point(n)
	}
	got, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if want := "S0.locked\nS4.downloaded:agent.exe\nS6.mutex\n"; string(got) != want {
		t.Fatalf("trace = %q, want %q", got, want)
	}
	t.Setenv("DMG_FAULT_TRACE", filepath.Join(t.TempDir(), "missing", "trace"))
	if err := Point("S0.locked"); err != nil {
		t.Fatalf("unwritable trace must not fail Point: %v", err)
	}
}

// TestHelperProcess is the subprocess body for the kill and hang tests.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("FAULTINJECT_HELPER") != "1" {
		t.Skip("helper")
	}
	proctest.Guard()
	os.Stdout.WriteString("ready\n")
	_ = Point("S6.state-temp")
	// Reached only if Point returned: stands in for caller cleanup.
	_ = os.WriteFile(os.Getenv("FAULTINJECT_MARKER"), []byte("returned"), 0o600)
	os.Exit(0)
}

func helper(t *testing.T, fault string) (*exec.Cmd, *bufio.Reader, string) {
	t.Helper()
	if err := Validate(fault); err != nil {
		t.Fatalf("bad fault spec %q: %v", fault, err)
	}
	marker := filepath.Join(t.TempDir(), "marker")
	cmd := proctest.Command(t, os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(cmd.Env, "FAULTINJECT_HELPER=1", "FAULTINJECT_MARKER="+marker, "DMG_FAULT="+fault)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd, bufio.NewReader(out), marker
}

func TestKillAndExitSkipCleanup(t *testing.T) {
	for action, want := range map[string]int{"kill": 137, "exit2": 2, "err": 0} {
		cmd, out, marker := helper(t, "S6.state-temp:"+action)
		_, _ = out.ReadString('\n')
		err := cmd.Wait()
		if got := cmd.ProcessState.ExitCode(); got != want {
			t.Fatalf("%s: wait = %v, exit %d, want %d", action, err, got, want)
		}
		_, statErr := os.Stat(marker)
		if returned := statErr == nil; returned != (want == 0) {
			t.Fatalf("%s: code after Point ran = %v", action, returned)
		}
	}
}

func TestHangBlocksUntilKilled(t *testing.T) {
	cmd, out, _ := helper(t, "S6.state-temp:hang")
	if line, _ := out.ReadString('\n'); line != "ready\n" {
		t.Fatalf("helper said %q", line)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("hang returned: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	_ = cmd.Process.Kill()
	<-done
}

func TestPointPanicAction(t *testing.T) {
	t.Setenv("DMG_FAULT", "S0.locked:panic")
	defer func() {
		if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "S0.locked") {
			t.Fatalf("recovered %v, want a faultinject panic", r)
		}
	}()
	_ = Point("S0.locked")
	t.Fatal("no panic")
}

// D28: sleep<duration> blocks at the checkpoint, then continues normally.
func TestPointSleepAction(t *testing.T) {
	t.Setenv("DMG_FAULT", "S6.mutex:sleep300ms")
	start := time.Now()
	if err := Point("S6.mutex"); err != nil {
		t.Fatalf("Point = %v, want nil after the sleep", err)
	}
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Fatalf("returned after %s", d)
	}
}
