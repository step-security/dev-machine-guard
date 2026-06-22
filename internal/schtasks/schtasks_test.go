package schtasks

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

func newTestLogger() *progress.Logger {
	return progress.NewLogger(progress.LevelInfo)
}

func TestIsConfigured_True(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "", 0, "schtasks", "/query", "/tn", taskName)

	got := isConfigured(context.Background(), mock)
	if !got {
		t.Error("expected isConfigured to return true when task exists")
	}
}

func TestIsConfigured_False(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/query", "/tn", taskName)

	got := isConfigured(context.Background(), mock)
	if got {
		t.Error("expected isConfigured to return false when task does not exist")
	}
}

func TestUninstall_Configured(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "", 0, "schtasks", "/query", "/tn", taskName)
	mock.SetCommand("SUCCESS: The scheduled task was successfully deleted.", "", 0, "schtasks", "/delete", "/tn", taskName, "/f")

	err := Uninstall(mock, newTestLogger())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestUninstall_NotConfigured(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/query", "/tn", taskName)

	err := Uninstall(mock, newTestLogger())
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestInstall_CreateFails(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetHomeDir(`C:\Users\testuser`)
	// Task doesn't exist
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/query", "/tn", taskName)

	// Note: Install calls os.Executable() and os.MkdirAll() which we can't mock,
	// but the schtasks /create will fail because we haven't stubbed it.
	err := Install(mock, newTestLogger())
	if err == nil {
		t.Fatal("expected error when schtasks /create is not stubbed")
	}
}

func TestResolveLogDir_NonAdmin(t *testing.T) {
	// paths.Home() is the primary source post-refactor. Drive it via
	// STEPSECURITY_HOME so the test exercises the same code path that
	// the launchd/systemd installers feed.
	t.Setenv("STEPSECURITY_HOME", `C:\Users\testuser\.stepsecurity`)

	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(false)
	mock.SetHomeDir(`C:\Users\testuser`)

	dir := resolveLogDir(mock)
	expected := `C:\Users\testuser\.stepsecurity`
	if dir != expected {
		t.Errorf("expected %s, got %s", expected, dir)
	}
}

func TestResolveLogDir_Admin(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetIsRoot(true)

	dir := resolveLogDir(mock)
	expected := `C:\ProgramData\StepSecurity`
	if dir != expected {
		t.Errorf("expected %s, got %s", expected, dir)
	}
}

// hourlySchedule mirrors what Install passes for the periodic task.
func hourlySchedule(hours int) []string {
	return []string{"/sc", "HOURLY", "/mo", strconv.Itoa(hours)}
}

func TestBuildCreateArgs_CustomFrequency(t *testing.T) {
	args := buildCreateArgs(taskName, `C:\agent.exe`, `C:\logs`, hourlySchedule(6), false)

	// Find the /mo argument and check its value
	foundMo := false
	for i, a := range args {
		if a == "/mo" && i+1 < len(args) {
			foundMo = true
			if args[i+1] != "6" {
				t.Errorf("expected /mo 6, got /mo %s", args[i+1])
			}
		}
	}
	if !foundMo {
		t.Error("expected /mo argument in schtasks create args")
	}
}

func TestBuildCreateArgs_Admin(t *testing.T) {
	args := buildCreateArgs(taskName, `C:\agent.exe`, `C:\ProgramData\StepSecurity`, hourlySchedule(4), true)

	foundRU := false
	for i, a := range args {
		if a == "/ru" && i+1 < len(args) {
			foundRU = true
			if args[i+1] != "INTERACTIVE" {
				t.Errorf("expected /ru INTERACTIVE, got /ru %s", args[i+1])
			}
		}
	}
	if !foundRU {
		t.Error("expected /ru INTERACTIVE for admin install")
	}
}

func TestBuildCreateArgs_NonAdmin(t *testing.T) {
	args := buildCreateArgs(taskName, `C:\agent.exe`, `C:\logs`, hourlySchedule(4), false)

	for _, a := range args {
		if a == "/ru" {
			t.Error("expected no /ru argument for non-admin install")
		}
	}
}

// The companion at-logon task uses /sc ONLOGON (no /mo) under its own name —
// this is the Windows "run on load" trigger.
func TestBuildCreateArgs_LogonTask(t *testing.T) {
	args := buildCreateArgs(logonTaskName, `C:\agent.exe`, `C:\logs`, []string{"/sc", "ONLOGON"}, false)

	if !argPairPresent(args, "/tn", logonTaskName) {
		t.Errorf("expected /tn %q in logon task args: %v", logonTaskName, args)
	}
	if !argPairPresent(args, "/sc", "ONLOGON") {
		t.Errorf("expected /sc ONLOGON in logon task args: %v", args)
	}
	for _, a := range args {
		if a == "/mo" {
			t.Errorf("logon (ONLOGON) task must not carry /mo: %v", args)
		}
	}
}

// trArg returns the value of the /tr argument (the task command).
func trArg(t *testing.T, args []string) string {
	t.Helper()
	for i, a := range args {
		if a == "/tr" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatal("no /tr argument found")
	return ""
}

// argPairPresent reports whether flag is immediately followed by value.
func argPairPresent(args []string, flag, value string) bool {
	for i, a := range args {
		if a == flag && i+1 < len(args) && args[i+1] == value {
			return true
		}
	}
	return false
}

// When the launcher binary is co-installed (MSI layout) it must be
// preferred over the agent so the scheduled task fires through the
// GUI-subsystem wrapper.
//
// Paths use forward slashes so the test is portable: filepath.{Dir,Join}
// in resolveTaskBinary follow the host OS separator. The Windows
// production path looks like C:\Program Files\StepSecurity\... — same
// logic, just darwin-incompatible to assert against directly.
func TestResolveTaskBinary_LauncherPresent(t *testing.T) {
	mock := executor.NewMock()
	agent := "/install/dir/stepsecurity-dev-machine-guard.exe"
	launcher := "/install/dir/stepsecurity-dev-machine-guard-task.exe"
	mock.SetFile(launcher, []byte{})

	if got := resolveTaskBinary(mock, agent); got != launcher {
		t.Errorf("want launcher %q, got %q", launcher, got)
	}
}

// Ad-hoc deploys may ship only the agent .exe. The task must still
// register correctly against the agent in that case.
func TestResolveTaskBinary_NoLauncher(t *testing.T) {
	mock := executor.NewMock()
	agent := "/install/dir/stepsecurity-dev-machine-guard.exe"

	if got := resolveTaskBinary(mock, agent); got != agent {
		t.Errorf("want agent fallback %q, got %q", agent, got)
	}
}

func TestRunNow_Success(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("SUCCESS: Attempted to run the scheduled task.", "", 0, "schtasks", "/run", "/tn", taskName)

	if err := RunNow(mock, newTestLogger()); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
}

func TestRunNow_NonZeroExit(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	mock.SetCommand("", "ERROR: The system cannot find the path specified.", 1, "schtasks", "/run", "/tn", taskName)

	err := RunNow(mock, newTestLogger())
	if err == nil {
		t.Fatal("expected error when schtasks /run exits non-zero")
	}
	if !strings.Contains(err.Error(), "exit code 1") {
		t.Errorf("expected exit code in error, got %v", err)
	}
}

// The task action must invoke the binary directly. A `cmd /c` wrapper
// (the pre-fix form) spawns a console window every time Task Scheduler
// fires the task under an interactive user session.
func TestBuildCreateArgs_TaskCommandFormat(t *testing.T) {
	args := buildCreateArgs(taskName, `C:\agent.exe`, `C:\ProgramData\StepSecurity`, hourlySchedule(4), true)

	taskCmd := trArg(t, args)

	if strings.Contains(strings.ToLower(taskCmd), "cmd /c") || strings.Contains(strings.ToLower(taskCmd), "cmd.exe") {
		t.Errorf("task command must not wrap binary in cmd: %q", taskCmd)
	}
	if !strings.Contains(taskCmd, "send-telemetry") {
		t.Errorf("task command missing send-telemetry: %q", taskCmd)
	}
	if !strings.Contains(taskCmd, `--install-dir="C:\ProgramData\StepSecurity"`) {
		t.Errorf("task command missing --install-dir flag: %q", taskCmd)
	}
	if !strings.HasPrefix(taskCmd, `"C:\agent.exe"`) {
		t.Errorf("task command must start with quoted binary path: %q", taskCmd)
	}
	if strings.Contains(taskCmd, ">>") || strings.Contains(taskCmd, "STEPSECURITY_HOME=") {
		t.Errorf("task command must not redirect output or set env vars: %q", taskCmd)
	}
}

// schtasks /create can't set battery/missed-run settings from the command
// line, so Install re-imports the task XML with them flipped. These exercise
// the pure patch/encode helpers (the schtasks round-trip itself needs Windows).
func TestPatchBatterySettings_FlipsPresentValues(t *testing.T) {
	xml := "<Task><Settings>" +
		"<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>" +
		"<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>" +
		"<StartWhenAvailable>false</StartWhenAvailable>" +
		"<Enabled>true</Enabled></Settings></Task>"
	out, changed := patchBatterySettings(xml)
	if !changed {
		t.Fatal("expected changed=true")
	}
	for _, want := range []string{
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
		"<StartWhenAvailable>true</StartWhenAvailable>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("patched XML missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "<StartWhenAvailable>false</StartWhenAvailable>") {
		t.Error("StartWhenAvailable should have flipped to true")
	}
}

func TestPatchBatterySettings_InjectsMissing(t *testing.T) {
	xml := "<Task><Settings><Enabled>true</Enabled></Settings></Task>"
	out, changed := patchBatterySettings(xml)
	if !changed {
		t.Fatal("expected changed=true (settings injected)")
	}
	for _, want := range []string{
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
		"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
		"<StartWhenAvailable>true</StartWhenAvailable>",
		"</Settings>",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("injected XML missing %q:\n%s", want, out)
		}
	}
}

func TestPatchBatterySettings_NoopWhenAlreadyDesired(t *testing.T) {
	xml := "<Task><Settings>" +
		"<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
		"<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" +
		"<StartWhenAvailable>true</StartWhenAvailable>" +
		"<RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure>" +
		"</Settings></Task>"
	if _, changed := patchBatterySettings(xml); changed {
		t.Error("expected changed=false when settings already desired")
	}
}

func TestPatchBatterySettings_AddsRetryOnFailure(t *testing.T) {
	xml := "<Task><Settings>" +
		"<DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>" +
		"<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>" +
		"<StartWhenAvailable>false</StartWhenAvailable>" +
		"</Settings></Task>"
	out, changed := patchBatterySettings(xml)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if !strings.Contains(out, "<RestartOnFailure><Interval>PT15M</Interval><Count>3</Count></RestartOnFailure>") {
		t.Errorf("expected RestartOnFailure block (15m / 3):\n%s", out)
	}
	// Must land inside <Settings>, not after it.
	if strings.Index(out, "<RestartOnFailure>") > strings.Index(out, "</Settings>") {
		t.Errorf("RestartOnFailure must be inside <Settings>:\n%s", out)
	}
}

func TestSetRestartOnFailure_ReplacesExisting(t *testing.T) {
	xml := "<Settings><RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure></Settings>"
	out := setRestartOnFailure(xml, "PT15M", 3)
	if !strings.Contains(out, "<Interval>PT15M</Interval>") {
		t.Errorf("expected interval replaced to PT15M:\n%s", out)
	}
	if strings.Contains(out, "PT1M") {
		t.Error("old PT1M interval should be gone")
	}
	if n := strings.Count(out, "<RestartOnFailure>"); n != 1 {
		t.Errorf("expected exactly one RestartOnFailure block, got %d:\n%s", n, out)
	}
}

func TestTaskXMLEncodeDecode_RoundTrip(t *testing.T) {
	orig := `<?xml version="1.0"?><Task><Settings><Enabled>true</Enabled></Settings></Task>`
	encoded := encodeTaskXMLUTF16(orig)
	if len(encoded) < 2 || encoded[0] != 0xFF || encoded[1] != 0xFE {
		t.Fatal("encoded output must start with a UTF-16LE BOM")
	}
	if got := decodeTaskXML(string(encoded)); got != orig {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, orig)
	}
}

func TestDecodeTaskXML_UTF8(t *testing.T) {
	s := "<Task/>"
	if got := decodeTaskXML(s); got != s {
		t.Errorf("UTF-8 passthrough = %q, want %q", got, s)
	}
	if got := decodeTaskXML("\xEF\xBB\xBF" + s); got != s {
		t.Errorf("UTF-8 BOM strip = %q, want %q", got, s)
	}
}
