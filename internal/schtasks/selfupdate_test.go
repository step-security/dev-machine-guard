package schtasks

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/launcher"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

const testBootstrap = `C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard-bootstrap.exe`

func TestUpdateTaskXML_WellFormedAndComplete(t *testing.T) {
	start := time.Date(2026, 10, 19, 13, 4, 5, 0, time.Local)
	doc := updateTaskXML(`C:\Program Files\A&B\`+launcher.BootstrapBinary, start)
	dec := xml.NewDecoder(strings.NewReader(strings.Replace(doc, `encoding="UTF-16"`, `encoding="UTF-8"`, 1)))
	for {
		_, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("not well-formed: %v\n%s", err, doc)
		}
	}
	for _, want := range []string{
		`<UserId>S-1-5-18</UserId>`,
		`<RunLevel>HighestAvailable</RunLevel>`,
		`<Interval>PT1H</Interval>`,
		`<RandomDelay>PT10M</RandomDelay>`,
		`<BootTrigger>`,
		`<Delay>PT15M</Delay>`,
		`<StartBoundary>2026-10-19T13:04:05</StartBoundary>`,
		`<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>`,
		`<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>`,
		`<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>`,
		`<StartWhenAvailable>true</StartWhenAvailable>`,
		`<ExecutionTimeLimit>PT30M</ExecutionTimeLimit>`,
		`<Command>C:\Program Files\A&amp;B\stepsecurity-dev-machine-guard-bootstrap.exe</Command>`,
		`<Arguments>update</Arguments>`,
		`<URI>\StepSecurity Dev Machine Guard (Update)</URI>`,
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("missing %s", want)
		}
	}
	// The XML must round-trip through the UTF-16 import encoding.
	if got := decodeTaskXML(string(encodeTaskXMLUTF16(doc))); got != doc {
		t.Fatal("UTF-16 round trip changed the XML")
	}
	if bad := updateTaskMismatches(doc, `C:\Program Files\A&B\`+launcher.BootstrapBinary); len(bad) != 0 {
		t.Fatalf("own XML mismatches: %v", bad)
	}
}

func TestUpdateTaskMismatches(t *testing.T) {
	doc := updateTaskXML(testBootstrap, time.Now())
	if bad := updateTaskMismatches(strings.Replace(doc, "S-1-5-18", "SYSTEM", 1), testBootstrap); len(bad) != 0 {
		t.Fatalf("SYSTEM by name rejected: %v", bad)
	}
	broken := strings.Replace(doc, "IgnoreNew", "Parallel", 1)
	broken = strings.Replace(broken, "<StartWhenAvailable>true", "<StartWhenAvailable>false", 1)
	if bad := updateTaskMismatches(broken, `C:\other.exe`); len(bad) != 3 {
		t.Fatalf("mismatches = %v", bad)
	}
}

func TestResolveBootstrapRoot(t *testing.T) {
	root := filepath.Join("/", "Program Files", "StepSecurity")
	mock := executor.NewMock()
	mock.SetFile(filepath.Join(root, launcher.BootstrapBinary), []byte{})
	for _, agent := range []string{
		filepath.Join(root, "seed", "1.2.3", "stepsecurity-dev-machine-guard.exe"),
		filepath.Join(root, "versions", "1.2.4", "stepsecurity-dev-machine-guard.exe"),
		filepath.Join(root, "stepsecurity-dev-machine-guard.exe"),
	} {
		if got, ok := resolveBootstrapRoot(mock, agent); !ok || got != root {
			t.Errorf("%s: root=%q ok=%v", agent, got, ok)
		}
	}
	for _, agent := range []string{
		filepath.Join(root, "other", "1.2.3", "stepsecurity-dev-machine-guard.exe"),
		filepath.Join("/", "elsewhere", "stepsecurity-dev-machine-guard.exe"),
	} {
		if _, ok := resolveBootstrapRoot(mock, agent); ok {
			t.Errorf("%s: unexpected bootstrap root", agent)
		}
	}
	if got := resolveTaskBinary(mock, filepath.Join(root, "seed", "1.2.3", "stepsecurity-dev-machine-guard.exe")); got != filepath.Join(root, launcher.BootstrapBinary) {
		t.Errorf("task binary = %q", got)
	}
}

func TestBuildCreateArgs_BootstrapRunVerb(t *testing.T) {
	args := buildCreateArgs(taskName, testBootstrap, `C:\ProgramData\StepSecurity`, hourlySchedule(4), true)
	want := `"` + testBootstrap + `" run send-telemetry --install-dir="C:\ProgramData\StepSecurity"`
	if got := trArg(t, args); got != want {
		t.Fatalf("/tr = %q, want %q", got, want)
	}
	if len(want) > 261 {
		t.Fatalf("/tr is %d chars; schtasks caps it at 261", len(want))
	}
	logon := buildCreateArgs(logonTaskName, testBootstrap, `C:\ProgramData\StepSecurity`, []string{"/sc", "ONLOGON"}, true)
	if got := trArg(t, logon); got != want {
		t.Fatalf("logon /tr = %q", got)
	}
	legacy := buildCreateArgs(taskName, `C:\x\stepsecurity-dev-machine-guard-task.exe`, `C:\d`, hourlySchedule(4), true)
	if got := trArg(t, legacy); strings.Contains(got, " run ") {
		t.Fatalf("legacy action got the run verb: %q", got)
	}
}

// updateTaskExec answers schtasks calls from a table and records them.
type updateTaskExec struct {
	*executor.Mock
	calls    []string
	present  map[string]bool
	queryXML string
	failOn   string
	files    map[string][]byte // captured /xml imports
}

func (e *updateTaskExec) Run(_ context.Context, name string, args ...string) (string, string, int, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	e.calls = append(e.calls, line)
	if e.failOn != "" && strings.Contains(line, e.failOn) {
		return "", "boom", 1, nil
	}
	if name != "schtasks" || len(args) < 3 {
		return "", "", 0, nil
	}
	task := args[2]
	switch args[0] {
	case "/query":
		if !e.present[task] {
			return "", "ERROR: not found", 1, nil
		}
		if len(args) > 3 && args[3] == "/xml" {
			return e.queryXML, "", 0, nil
		}
	case "/delete":
		delete(e.present, task)
	case "/create":
		if len(args) > 4 && args[3] == "/xml" {
			data, _ := os.ReadFile(args[4])
			e.files[task] = data
		}
		e.present[task] = true
	}
	return "", "", 0, nil
}

func newUpdateTaskExec() *updateTaskExec {
	return &updateTaskExec{Mock: executor.NewMock(), present: map[string]bool{}, files: map[string][]byte{}}
}

func TestInstallUpdateTask_ImportsAndVerifies(t *testing.T) {
	e := newUpdateTaskExec()
	now := time.Date(2026, 10, 19, 1, 2, 3, 0, time.Local)
	e.queryXML = string(encodeTaskXMLUTF16(updateTaskXML(testBootstrap, now)))
	log := progress.NewLogger(progress.LevelInfo)
	if err := installUpdateTask(context.Background(), e, log, testBootstrap, now); err != nil {
		t.Fatal(err)
	}
	got := decodeTaskXML(string(e.files[updateTaskName]))
	if got != updateTaskXML(testBootstrap, now) {
		t.Fatalf("imported XML differs:\n%s", got)
	}
	if !strings.HasPrefix(string(e.files[updateTaskName]), "\xff\xfe") {
		t.Fatal("import file is not UTF-16LE with BOM")
	}
	// Idempotent: a second install overwrites (/f) and verifies again.
	if err := installUpdateTask(context.Background(), e, log, testBootstrap, now); err != nil {
		t.Fatal(err)
	}
	for _, c := range e.calls {
		if strings.HasPrefix(c, "schtasks /create") && !strings.HasSuffix(c, "/f") {
			t.Fatalf("create without /f: %s", c)
		}
	}
}

func TestInstallUpdateTask_VerifyFailure(t *testing.T) {
	e := newUpdateTaskExec()
	e.queryXML = strings.Replace(updateTaskXML(testBootstrap, time.Now()), "IgnoreNew", "Queue", 1)
	if err := installUpdateTask(context.Background(), e, newTestLogger(), testBootstrap, time.Now()); err == nil || !strings.Contains(err.Error(), "MultipleInstancesPolicy") {
		t.Fatalf("err = %v", err)
	}
	e = newUpdateTaskExec()
	e.failOn = "/create"
	if err := installUpdateTask(context.Background(), e, newTestLogger(), testBootstrap, time.Now()); err == nil {
		t.Fatal("expected create failure")
	}
}

func stubPlatformHooks(t *testing.T) (stopped *string, regDeleted *bool) {
	t.Helper()
	var s string
	var r bool
	oldStop, oldReg, oldExe := stopDMGProcesses, deleteRunningVerReg, executablePath
	stopDMGProcesses = func(root string, wait time.Duration, _ *progress.Logger) error {
		if wait != stopProcessesWait {
			t.Errorf("wait = %s", wait)
		}
		s = root
		return nil
	}
	deleteRunningVerReg = func() error { r = true; return nil }
	t.Cleanup(func() { stopDMGProcesses, deleteRunningVerReg, executablePath = oldStop, oldReg, oldExe })
	return &s, &r
}

func TestUninstall_BootstrapRemovesEverything(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"versions/1.2.3", "state", "seed/1.2.3"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "state", "state.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	stopped, reg := stubPlatformHooks(t)
	executablePath = func() (string, error) {
		return filepath.Join(root, "seed", "1.2.3", "stepsecurity-dev-machine-guard.exe"), nil
	}

	e := newUpdateTaskExec()
	e.SetFile(filepath.Join(root, launcher.BootstrapBinary), []byte{})
	e.present[taskName] = true
	e.present[updateTaskName] = true // logon task already gone: not an error
	if err := Uninstall(e, newTestLogger()); err != nil {
		t.Fatal(err)
	}
	if len(e.present) != 0 {
		t.Fatalf("tasks left: %v", e.present)
	}
	if *stopped != root || !*reg {
		t.Fatalf("stopped=%q reg=%v", *stopped, *reg)
	}
	for _, d := range []string{"versions", "state"} {
		if _, err := os.Stat(filepath.Join(root, d)); !os.IsNotExist(err) {
			t.Fatalf("%s not removed", d)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "seed")); err != nil {
		t.Fatal("seed is MSI-owned and must be left to the MSI")
	}
}

func TestUninstall_BootstrapContinuesPastFailures(t *testing.T) {
	root := t.TempDir()
	stopDone, _ := stubPlatformHooks(t)
	executablePath = func() (string, error) {
		return filepath.Join(root, "seed", "1.2.3", "stepsecurity-dev-machine-guard.exe"), nil
	}
	e := newUpdateTaskExec()
	e.SetFile(filepath.Join(root, launcher.BootstrapBinary), []byte{})
	e.present[taskName] = true
	e.present[updateTaskName] = true
	e.failOn = "/delete /tn " + taskName + " /f"
	err := Uninstall(e, newTestLogger())
	if err == nil {
		t.Fatal("expected the failed delete to be reported")
	}
	if e.present[updateTaskName] || *stopDone != root {
		t.Fatal("later steps skipped after a failure")
	}
}

func TestUninstall_LegacyLeavesUpdateTask(t *testing.T) {
	stubPlatformHooks(t)
	executablePath = func() (string, error) { return filepath.Join(t.TempDir(), "stepsecurity-dev-machine-guard.exe"), nil }
	e := newUpdateTaskExec()
	e.present[taskName] = true
	e.present[updateTaskName] = true
	if err := Uninstall(e, newTestLogger()); err != nil {
		t.Fatal(err)
	}
	if !e.present[updateTaskName] {
		t.Fatal("a non-bootstrap uninstall deleted the MSI's update task (M-2)")
	}
}
