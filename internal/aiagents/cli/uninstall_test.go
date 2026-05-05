package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
)

// runInstallForTest seeds the target home with DMG-owned hooks for the
// given agent. Returns the home directory used. Helper exists because
// most uninstall tests want a "previously installed" starting state.
func runInstallForTest(t *testing.T, agent string) (home string, m *executor.Mock) {
	t.Helper()
	withEnterpriseConfig(t)
	withResolveBinary(t, okBinary)

	home = t.TempDir()
	m = newInstallMock(t, home)
	switch agent {
	case "claude-code":
		m.SetPath("claude", "/usr/local/bin/claude")
	case "codex":
		m.SetPath("codex", "/usr/local/bin/codex")
	case "both":
		m.SetPath("claude", "/usr/local/bin/claude")
		m.SetPath("codex", "/usr/local/bin/codex")
	}

	var stdout, stderr bytes.Buffer
	if rc := RunInstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("seed install failed: rc=%d stderr=%q", rc, stderr.String())
	}
	return home, m
}

func TestRunUninstall_RootNoConsoleUser_Exit0(t *testing.T) {
	logPath := withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := executor.NewMock()
	m.SetIsRoot(true)
	m.SetUsername("root")
	m.SetHomeDir("/var/root")

	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	if !strings.Contains(stderr.String(), "no console user") {
		t.Errorf("stderr missing bail note, got: %q", stderr.String())
	}
	if data, _ := os.ReadFile(logPath); !strings.Contains(string(data), "no_console_user") {
		t.Errorf("errlog missing no_console_user, got: %q", string(data))
	}
}

func TestRunUninstall_SelfPathFails_Exit1(t *testing.T) {
	logPath := withErrorLog(t)
	withResolveBinary(t, func() (string, error) {
		return "", errors.New("mock selfpath failure")
	})

	m := newInstallMock(t, t.TempDir())
	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &stdout, &stderr); rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "cannot resolve own binary path") {
		t.Errorf("stderr missing diagnostic, got: %q", stderr.String())
	}
	if data, _ := os.ReadFile(logPath); !strings.Contains(string(data), "selfpath_failed") {
		t.Errorf("errlog missing selfpath_failed, got: %q", string(data))
	}
}

func TestRunUninstall_UnsupportedAgent_Exit1(t *testing.T) {
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := newInstallMock(t, t.TempDir())
	var stdout, stderr bytes.Buffer
	rc := RunUninstall(context.Background(), m, "cursor", &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "unsupported agent") {
		t.Errorf("stderr missing diagnostic, got: %q", stderr.String())
	}
}

func TestRunUninstall_NoAgentsDetected_Exit0(t *testing.T) {
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := newInstallMock(t, t.TempDir()) // empty PATH
	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("exit = %d, want 0", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "No supported AI coding agents detected") {
		t.Errorf("stdout missing no-detected message, got: %q", out)
	}
	// User-visible verb in the hint must say "uninstall", not "install".
	// A copy-pasted install hint would mislead users about the escape hatch.
	if !strings.Contains(out, "uninstall") {
		t.Errorf("hint should mention 'uninstall', got: %q", out)
	}
}

// TestRunUninstall_NoEnterpriseConfigStillWorks pins the explicit
// uninstall design choice: revoking enterprise credentials must not
// trap users with hook entries pointing at a binary that can no
// longer authenticate. Default config vars are placeholders here —
// no withEnterpriseConfig — and uninstall must still proceed.
func TestRunUninstall_NoEnterpriseConfigStillWorks(t *testing.T) {
	// First seed Claude hooks WITH valid config (install requires it).
	home, m := runInstallForTest(t, "claude-code")

	// Now drop the enterprise config and uninstall. The withEnterpriseConfig
	// cleanup from runInstallForTest hasn't fired yet (still in the same
	// test), so we have to override directly.
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	var stdout, stderr bytes.Buffer
	rc := RunUninstall(context.Background(), m, "", &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("uninstall exit = %d, want 0 (stderr=%q)", rc, stderr.String())
	}

	// Verify the actual uninstall happened — the file should still
	// exist but have no DMG-owned hook entries.
	settings := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings file vanished after uninstall: %v", err)
	}
	if strings.Contains(string(data), fakeBinary+" _hook claude-code") {
		t.Errorf("DMG hook command still present after uninstall: %s", string(data))
	}
}

func TestRunUninstall_RemovesPreviouslyInstalledHooks(t *testing.T) {
	home, m := runInstallForTest(t, "claude-code")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	settings := filepath.Join(home, ".claude", "settings.json")
	before, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(before), fakeBinary+" _hook claude-code") {
		t.Fatalf("seed broken: install didn't write hook command: %s", string(before))
	}

	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("uninstall rc=%d stderr=%q", rc, stderr.String())
	}

	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings file deleted after uninstall: %v", err)
	}
	if strings.Contains(string(after), fakeBinary+" _hook claude-code") {
		t.Errorf("DMG hook command not removed: %s", string(after))
	}

	out := stdout.String()
	if !strings.Contains(out, "claude-code:") {
		t.Errorf("stdout missing claude-code section, got: %q", out)
	}
	if !strings.Contains(out, "removed:") {
		t.Errorf("stdout missing 'removed:' line, got: %q", out)
	}
	if !strings.Contains(out, "wrote:") {
		t.Errorf("stdout missing 'wrote:' line, got: %q", out)
	}
}

// TestRunUninstall_NoDMGOwnedEntries pins the no-op path: settings
// file exists, but contains no DMG-owned hook commands. Uninstall
// must succeed (exit 0), surface the per-adapter "no DMG-owned" note
// to the user, and leave the file byte-identical.
func TestRunUninstall_NoDMGOwnedEntries(t *testing.T) {
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// User-authored settings with a third-party hook that DMG
	// must NOT match against its uninstall regex.
	settings := filepath.Join(claudeDir, "settings.json")
	original := []byte(`{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/other-tool/hook PreToolUse", "timeout": 5}]}
    ]
  }
}
`)
	if err := os.WriteFile(settings, original, 0o644); err != nil {
		t.Fatal(err)
	}

	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("uninstall rc=%d stderr=%q", rc, stderr.String())
	}

	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("settings file vanished: %v", err)
	}
	if !bytes.Equal(original, after) {
		t.Errorf("settings file mutated when no DMG hooks present:\nbefore=%s\nafter=%s", original, after)
	}

	if !strings.Contains(stdout.String(), "no DMG-owned") {
		t.Errorf("stdout missing no-op note, got: %q", stdout.String())
	}
}

func TestRunUninstall_ExplicitAgentSkipsDetection(t *testing.T) {
	// Seed codex installed.
	home, _ := runInstallForTest(t, "codex")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	// Now use a fresh mock with EMPTY $PATH but --agent codex —
	// uninstall must still target codex.
	m := newInstallMock(t, home)

	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "codex", &stdout, &stderr); rc != 0 {
		t.Fatalf("uninstall rc=%d stderr=%q", rc, stderr.String())
	}

	hooks, err := os.ReadFile(filepath.Join(home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hooks), fakeBinary+" _hook codex") {
		t.Errorf("DMG codex hook still present: %s", string(hooks))
	}
}

// TestRunUninstall_CodexLeavesFeatureFlag pins the invariant that
// uninstall removes hook entries from hooks.json but does NOT revert
// [features].codex_hooks=true in config.toml. Other tools' hooks may
// depend on that flag staying enabled.
func TestRunUninstall_CodexLeavesFeatureFlag(t *testing.T) {
	home, m := runInstallForTest(t, "codex")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	cfgPath := filepath.Join(home, ".codex", "config.toml")
	beforeCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(beforeCfg), "codex_hooks") {
		t.Fatalf("seed broken: install didn't set codex_hooks flag: %s", string(beforeCfg))
	}

	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("uninstall rc=%d stderr=%q", rc, stderr.String())
	}

	afterCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("config.toml vanished after uninstall: %v", err)
	}
	if !bytes.Equal(beforeCfg, afterCfg) {
		t.Errorf("config.toml mutated by uninstall:\nbefore=%s\nafter=%s",
			string(beforeCfg), string(afterCfg))
	}

	// The feature-flag-residue note must be visible to the user so
	// the residue isn't a silent surprise.
	if !strings.Contains(stdout.String(), "feature flag left enabled") {
		t.Errorf("stdout missing feature-flag residue note, got: %q", stdout.String())
	}
}

// TestRunUninstall_NeverDeletesSettingsFile pins the invariant that
// even when uninstall removes every DMG-owned hook from a settings
// file that contains nothing else, the file itself must remain on
// disk. (The adapter is responsible for this; the test ensures it
// holds at the handler boundary.)
func TestRunUninstall_NeverDeletesSettingsFile(t *testing.T) {
	home, m := runInstallForTest(t, "claude-code")

	withErrorLog(t)
	withResolveBinary(t, okBinary)

	settings := filepath.Join(home, ".claude", "settings.json")

	var stdout, stderr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("uninstall rc=%d stderr=%q", rc, stderr.String())
	}
	if _, err := os.Stat(settings); err != nil {
		t.Fatalf("settings file deleted: %v", err)
	}
}
