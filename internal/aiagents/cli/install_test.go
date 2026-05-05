package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
)

// withEnterpriseConfig stages valid (non-empty, non-placeholder) values
// in the package-level config vars that ingest.Snapshot reads, restoring
// the previous values on cleanup. Tests using this helper must not run
// in parallel — config vars are package-level state.
func withEnterpriseConfig(t *testing.T) {
	t.Helper()
	prevCID, prevEP, prevAK := config.CustomerID, config.APIEndpoint, config.APIKey
	config.CustomerID = "cust-test"
	config.APIEndpoint = "https://api.example.com"
	config.APIKey = "secret-test"
	t.Cleanup(func() {
		config.CustomerID = prevCID
		config.APIEndpoint = prevEP
		config.APIKey = prevAK
	})
}

// withResolveBinary overrides the install-time selfpath resolver with a
// fixed value (or error). The default Resolve() reads os.Executable
// which under `go test` points at the test binary — fine in principle,
// but pinning a known value keeps the hook commands written to settings
// readable in failure output.
func withResolveBinary(t *testing.T, fn func() (string, error)) {
	t.Helper()
	prev := resolveBinary
	resolveBinary = fn
	t.Cleanup(func() { resolveBinary = prev })
}

const fakeBinary = "/usr/local/bin/stepsecurity-dev-machine-guard"

func okBinary() (string, error) { return fakeBinary, nil }

// newInstallMock returns a Mock executor configured as a non-root user
// whose home is `home`. Callers add SetPath entries for the agents they
// want detected.
func newInstallMock(t *testing.T, home string) *executor.Mock {
	t.Helper()
	m := executor.NewMock()
	m.SetIsRoot(false)
	m.SetUsername("alice")
	m.SetHomeDir(home)
	return m
}

func TestRunInstall_NoEnterpriseConfig_Exit1(t *testing.T) {
	logPath := withErrorLog(t)
	// Leave config vars as their default placeholders ({{...}}) — no
	// withEnterpriseConfig call. ingest.Snapshot returns ok=false on
	// placeholders.

	var stdout, stderr bytes.Buffer
	m := executor.NewMock()
	rc := RunInstall(context.Background(), m, "", &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "Enterprise configuration not found") {
		t.Errorf("stderr missing diagnostic, got: %q", stderr.String())
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected errors log entry: %v", err)
	}
	if !strings.Contains(string(data), "enterprise_config_missing") {
		t.Errorf("errlog missing code, got: %q", string(data))
	}
}

func TestRunInstall_PlaceholderConfig_Exit1(t *testing.T) {
	withErrorLog(t)
	// Explicitly stage a placeholder in one field — the stricter gate
	// must reject build-time placeholders even when the other two
	// values look valid.
	prevCID, prevEP, prevAK := config.CustomerID, config.APIEndpoint, config.APIKey
	config.CustomerID = "cust-1"
	config.APIEndpoint = "{{API_ENDPOINT}}"
	config.APIKey = "secret"
	t.Cleanup(func() {
		config.CustomerID = prevCID
		config.APIEndpoint = prevEP
		config.APIKey = prevAK
	})

	var stdout, stderr bytes.Buffer
	m := executor.NewMock()
	if rc := RunInstall(context.Background(), m, "", &stdout, &stderr); rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
}

func TestRunInstall_RootNoConsoleUser_Exit0(t *testing.T) {
	withEnterpriseConfig(t)
	logPath := withErrorLog(t)
	withResolveBinary(t, okBinary)

	m := executor.NewMock()
	m.SetIsRoot(true)
	// "root" simulates the executor failing to resolve a console user.
	m.SetUsername("root")
	m.SetHomeDir("/var/root")

	var stdout, stderr bytes.Buffer
	rc := RunInstall(context.Background(), m, "", &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("root + no console user: exit = %d, want 0", rc)
	}
	if !strings.Contains(stderr.String(), "no console user") {
		t.Errorf("stderr missing the bail note, got: %q", stderr.String())
	}
	// errors.jsonl should record the bail.
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("expected errlog entry on root-no-console-user: %v", err)
	}
	if !strings.Contains(string(data), "no_console_user") {
		t.Errorf("errlog missing no_console_user code, got: %q", string(data))
	}
}

func TestRunInstall_SelfPathFails_Exit1(t *testing.T) {
	withEnterpriseConfig(t)
	logPath := withErrorLog(t)
	withResolveBinary(t, func() (string, error) {
		return "", errors.New("mock selfpath failure")
	})

	home := t.TempDir()
	m := newInstallMock(t, home)

	var stdout, stderr bytes.Buffer
	if rc := RunInstall(context.Background(), m, "", &stdout, &stderr); rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "cannot resolve own binary path") {
		t.Errorf("stderr missing diagnostic, got: %q", stderr.String())
	}
	if data, _ := os.ReadFile(logPath); !strings.Contains(string(data), "selfpath_failed") {
		t.Errorf("errlog missing selfpath_failed code, got: %q", string(data))
	}
}

func TestRunInstall_UnsupportedAgent_Exit1(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)

	var stdout, stderr bytes.Buffer
	rc := RunInstall(context.Background(), m, "cursor", &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("exit = %d, want 1", rc)
	}
	if !strings.Contains(stderr.String(), "unsupported agent") {
		t.Errorf("stderr missing unsupported-agent diagnostic, got: %q", stderr.String())
	}
}

func TestRunInstall_NoAgentsDetected_Exit0(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home) // no SetPath, nothing detected

	var stdout, stderr bytes.Buffer
	rc := RunInstall(context.Background(), m, "", &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (no detection is not an error)", rc)
	}
	out := stdout.String()
	if !strings.Contains(out, "No supported AI coding agents detected") {
		t.Errorf("stdout missing no-detected message, got: %q", out)
	}
	// User should learn about the --agent escape hatch and the agent
	// names — without that they have no way to recover from a buggy
	// detection result.
	if !strings.Contains(out, "--agent") || !strings.Contains(out, "claude-code") || !strings.Contains(out, "codex") {
		t.Errorf("stdout missing --agent escape-hatch hint, got: %q", out)
	}
}

func TestRunInstall_InstallsClaudeCode(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	var stdout, stderr bytes.Buffer
	rc := RunInstall(context.Background(), m, "", &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", rc, stderr.String())
	}

	settings := filepath.Join(home, ".claude", "settings.json")
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("expected settings file written at %s: %v", settings, err)
	}
	// The hook command must include the resolved binary path AND the
	// canonical `_hook claude-code` invocation prefix — that's what
	// uninstall later matches against.
	if !strings.Contains(string(data), fakeBinary+" _hook claude-code") {
		t.Errorf("settings missing hook command, got: %s", string(data))
	}

	out := stdout.String()
	if !strings.Contains(out, "claude-code:") {
		t.Errorf("stdout missing claude-code header, got: %q", out)
	}
	if !strings.Contains(out, "added:") {
		t.Errorf("stdout missing added hooks line, got: %q", out)
	}
	if !strings.Contains(out, "wrote:") {
		t.Errorf("stdout missing wrote line, got: %q", out)
	}
}

func TestRunInstall_InstallsBoth(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")
	m.SetPath("codex", "/usr/local/bin/codex")

	var stdout, stderr bytes.Buffer
	rc := RunInstall(context.Background(), m, "", &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", rc, stderr.String())
	}

	for _, p := range []string{
		filepath.Join(home, ".claude", "settings.json"),
		filepath.Join(home, ".codex", "hooks.json"),
		filepath.Join(home, ".codex", "config.toml"),
	} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected file written: %s (err=%v)", p, err)
		}
	}

	out := stdout.String()
	// Per-adapter sections appear in declaration order: claude-code first.
	if claudeIdx, codexIdx := strings.Index(out, "claude-code:"), strings.Index(out, "codex:"); claudeIdx == -1 || codexIdx == -1 || claudeIdx > codexIdx {
		t.Errorf("expected claude-code section before codex; got: %q", out)
	}
}

func TestRunInstall_ExplicitAgentSkipsDetection(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	// PATH is empty — but --agent codex is an unconditional opt-in.
	m := newInstallMock(t, home)

	var stdout, stderr bytes.Buffer
	rc := RunInstall(context.Background(), m, "codex", &stdout, &stderr)
	if rc != 0 {
		t.Fatalf("exit = %d, want 0 (stderr=%q)", rc, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".codex", "hooks.json")); err != nil {
		t.Errorf("expected codex hooks.json: %v", err)
	}
	// Claude must NOT have been touched.
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("claude settings should not exist on explicit --agent codex; err=%v", err)
	}
}

func TestRunInstall_IdempotentReinstall(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := t.TempDir()
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	var out1 bytes.Buffer
	if rc := RunInstall(context.Background(), m, "", &out1, &bytes.Buffer{}); rc != 0 {
		t.Fatalf("first install exit = %d", rc)
	}

	settings := filepath.Join(home, ".claude", "settings.json")
	first, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}

	var out2 bytes.Buffer
	if rc := RunInstall(context.Background(), m, "", &out2, &bytes.Buffer{}); rc != 0 {
		t.Fatalf("second install exit = %d", rc)
	}

	second, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	// A reinstall pretty-prints into canonical formatting; what we
	// care about is byte-stability across two reinstalls — that
	// confirms upsertHook produced no spurious diff after settling.
	if !bytes.Equal(first, second) {
		t.Errorf("settings drifted between reinstalls:\n--- first ---\n%s\n--- second ---\n%s", string(first), string(second))
	}

	// Second run's stdout should report the entries as unchanged.
	if !strings.Contains(out2.String(), "unchanged:") {
		t.Errorf("second-install stdout missing 'unchanged:' line, got: %q", out2.String())
	}
}

// TestRunInstall_UsesTargetUserHomeNotProcessHome pins the wiring
// between ResolveTargetUser and selectAdapters: the install must
// target the resolved user's home, not the calling process's $HOME.
// Plugging the mock home into a path that os.UserHomeDir would never
// return is the cheapest way to verify which path actually got used.
func TestRunInstall_UsesTargetUserHomeNotProcessHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The test home contains characters Windows accepts but the
		// rest of the suite already covers Mac/Linux paths cleanly.
		t.Skip("path-shape assertion is Unix-flavored")
	}
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)

	home := filepath.Join(t.TempDir(), "explicit-target-home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	var stdout, stderr bytes.Buffer
	if rc := RunInstall(context.Background(), m, "", &stdout, &stderr); rc != 0 {
		t.Fatalf("exit = %d (stderr=%q)", rc, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Errorf("install did not write under target-user home: %v", err)
	}
}
