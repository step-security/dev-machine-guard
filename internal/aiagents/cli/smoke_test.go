package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSmoke_InstallInvokeUninstall is the end-to-end smoke test:
// drives RunInstall → RunHook → RunUninstall against a single temp HOME
// and confirms the on-disk lifecycle matches what we tell users to expect.
//
// Why this is a separate test from the per-handler unit tests:
//   - install/uninstall unit tests use the executor mock's HomeDir, but
//     RunHook resolves home from os.UserHomeDir(); the install path the
//     hook will be invoked from must match the executor's HomeDir for
//     the round-trip to be meaningful.
//   - the seam-stubbed hook tests prove the runtime emits a well-formed
//     allow response, but they don't prove that the very settings file
//     RunInstall just wrote is the one the agent would invoke against.
func TestSmoke_InstallInvokeUninstall(t *testing.T) {
	withEnterpriseConfig(t)
	withErrorLog(t)
	withResolveBinary(t, okBinary)
	withStubUploader(t)

	home := t.TempDir()
	// RunHook reads HOME via os.UserHomeDir; align it with the executor's
	// HomeDir so install writes and hook resolves to the same tree.
	// os.UserHomeDir checks $HOME on Unix and $USERPROFILE on Windows —
	// set both so the smoke test is platform-agnostic.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	m := newInstallMock(t, home)
	m.SetPath("claude", "/usr/local/bin/claude")

	var instOut, instErr bytes.Buffer
	if rc := RunInstall(context.Background(), m, "", &instOut, &instErr); rc != 0 {
		t.Fatalf("install: rc=%d stderr=%q", rc, instErr.String())
	}

	settings := filepath.Join(home, ".claude", "settings.json")
	postInstall, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("install did not produce settings: %v", err)
	}
	if !strings.Contains(string(postInstall), fakeBinary+" _hook claude-code") {
		t.Fatalf("settings missing hook command after install: %s", postInstall)
	}

	var hookOut, hookErr bytes.Buffer
	rc := RunHook(
		strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`),
		&hookOut, &hookErr,
		[]string{"claude-code", "PreToolUse"},
	)
	if rc != 0 {
		t.Fatalf("hook: rc=%d stderr=%q", rc, hookErr.String())
	}
	if hookErr.Len() != 0 {
		t.Fatalf("hook stderr non-empty: %q", hookErr.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(hookOut.Bytes()), &resp); err != nil {
		t.Fatalf("hook stdout not valid JSON: %v: %q", err, hookOut.Bytes())
	}
	if resp["continue"] != true {
		t.Fatalf("hook allow response missing continue=true: %v", resp)
	}

	var unOut, unErr bytes.Buffer
	if rc := RunUninstall(context.Background(), m, "", &unOut, &unErr); rc != 0 {
		t.Fatalf("uninstall: rc=%d stderr=%q", rc, unErr.String())
	}

	postUninstall, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("uninstall removed the settings file (it should only edit it): %v", err)
	}
	if strings.Contains(string(postUninstall), fakeBinary+" _hook claude-code") {
		t.Fatalf("uninstall left DMG-owned hook in settings: %s", postUninstall)
	}
	if !strings.Contains(unOut.String(), "removed:") {
		t.Errorf("uninstall summary missing removed line, got: %q", unOut.String())
	}
}
