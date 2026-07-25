package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

func TestAICLIDetector_FindsClaude(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("claude", "/usr/local/bin/claude")
	mock.SetCommand("1.0.12\n", "", 0, "/usr/local/bin/claude", "--version")
	mock.SetDir("/Users/testuser/.claude")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "claude-code" {
			found = true
			if r.Version != "1.0.12" {
				t.Errorf("expected version 1.0.12, got %s", r.Version)
			}
			if r.BinaryPath != "/usr/local/bin/claude" {
				t.Errorf("expected /usr/local/bin/claude, got %s", r.BinaryPath)
			}
			if r.ConfigDir != "/Users/testuser/.claude" {
				t.Errorf("expected config dir /Users/testuser/.claude, got %s", r.ConfigDir)
			}
			if r.Type != "cli_tool" {
				t.Errorf("expected type cli_tool, got %s", r.Type)
			}
		}
	}
	if !found {
		t.Error("claude-code not found in results")
	}
}

func TestAICLIDetector_NoToolsFound(t *testing.T) {
	mock := executor.NewMock()
	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	if len(results) != 0 {
		t.Errorf("expected 0 tools, got %d", len(results))
	}
}

func TestAICLIDetector_RejectsCopilotInstallPrompt(t *testing.T) {
	shimPath := "/Users/testuser/Library/Application Support/Code/User/globalStorage/github.copilot-chat/copilotCli/copilot"
	mock := executor.NewMock()
	mock.SetPath("copilot", shimPath)
	mock.SetCommand("? GitHub Copilot CLI is not installed. Would you like to install it? (Y/n)\n", "", 0, shimPath, "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	for _, r := range results {
		if r.Name == "github-copilot-cli" {
			t.Errorf("github-copilot-cli should not be detected when --version returns the install prompt; got %+v", r)
		}
	}
}

func TestAICLIDetector_RejectsCopilotNonZeroExit(t *testing.T) {
	shimPath := "/usr/local/bin/copilot"
	mock := executor.NewMock()
	mock.SetPath("copilot", shimPath)
	// Output matches the version regex but exit code is non-zero — should be rejected.
	mock.SetCommand("copilot 1.2 internal error\n", "", 1, shimPath, "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	for _, r := range results {
		if r.Name == "github-copilot-cli" {
			t.Errorf("github-copilot-cli should not be detected when --version exits non-zero; got %+v", r)
		}
	}
}

func TestAICLIDetector_AcceptsRealCopilotVersion(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("copilot", "/usr/local/bin/copilot")
	mock.SetCommand("GitHub Copilot CLI version 0.0.336\n", "", 0, "/usr/local/bin/copilot", "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "github-copilot-cli" {
			found = true
			if r.Version != "0.0.336" {
				t.Errorf("expected version 0.0.336, got %s", r.Version)
			}
			if r.BinaryPath != "/usr/local/bin/copilot" {
				t.Errorf("expected /usr/local/bin/copilot, got %s", r.BinaryPath)
			}
		}
	}
	if !found {
		t.Error("github-copilot-cli not found in results")
	}
}

func TestAICLIDetector_VersionUnknown(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("codex", "/usr/local/bin/codex")
	mock.SetCommand("", "", 1, "/usr/local/bin/codex", "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "codex" {
			found = true
			if r.Version != "unknown" {
				t.Errorf("expected unknown, got %s", r.Version)
			}
		}
	}
	if !found {
		t.Error("codex not found")
	}
}

func TestAICLIDetector_FindsCursorAgent(t *testing.T) {
	mock := executor.NewMock()
	mock.SetPath("cursor-agent", "/usr/local/bin/cursor-agent")
	mock.SetCommand("2026.02.27-e7d2ef6\n", "", 0, "/usr/local/bin/cursor-agent", "--version")
	mock.SetDir("/Users/testuser/.cursor")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "cursor-agent" {
			found = true
			if r.Vendor != "Cursor" {
				t.Errorf("expected vendor Cursor, got %s", r.Vendor)
			}
			if r.Type != "cli_tool" {
				t.Errorf("expected type cli_tool, got %s", r.Type)
			}
			if r.Version != "2026.02.27-e7d2ef6" {
				t.Errorf("expected version 2026.02.27-e7d2ef6, got %s", r.Version)
			}
			if r.BinaryPath != "/usr/local/bin/cursor-agent" {
				t.Errorf("expected /usr/local/bin/cursor-agent, got %s", r.BinaryPath)
			}
			if r.ConfigDir != "/Users/testuser/.cursor" {
				t.Errorf("expected config dir /Users/testuser/.cursor, got %s", r.ConfigDir)
			}
		}
	}
	if !found {
		t.Error("cursor-agent not found in results")
	}
}

func TestAICLIDetector_FindsPatchWardenFromNPMMetadata(t *testing.T) {
	mock := executor.NewMock()
	shim := "/usr/local/bin/patchwarden"
	target := "/usr/local/lib/node_modules/patchwarden/dist/index.js"
	pkgRoot := "/usr/local/lib/node_modules/patchwarden"
	mock.SetPath("patchwarden", shim)
	mock.SetSymlink(shim, target)
	mock.SetFile(pkgRoot+"/package.json", []byte(`{"name":"patchwarden","version":"1.6.2"}`))

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	var got *model.AITool
	for i, result := range results {
		if result.Name == "patchwarden" {
			got = &results[i]
			break
		}
	}
	if got == nil {
		t.Fatal("patchwarden not found")
	}
	if got.Vendor != "OpenSource" {
		t.Errorf("expected vendor OpenSource, got %s", got.Vendor)
	}
	if got.Type != "cli_tool" {
		t.Errorf("expected type cli_tool, got %s", got.Type)
	}
	if got.Version != "1.6.2" {
		t.Errorf("expected version 1.6.2 from npm metadata, got %s", got.Version)
	}
	if got.BinaryPath != shim {
		t.Errorf("expected binary_path %s, got %s", shim, got.BinaryPath)
	}
	if got.InstallPath != pkgRoot {
		t.Errorf("expected install_path %s, got %s", pkgRoot, got.InstallPath)
	}
	if got.ConfigDir != "" {
		t.Errorf("expected no user-level config dir, got %s", got.ConfigDir)
	}
}

func TestAICLIDetector_PatchWardenSkipsVersionExecutionWithoutMetadata(t *testing.T) {
	mock := executor.NewMock()
	bin := "/usr/local/bin/patchwarden"
	mock.SetPath("patchwarden", bin)
	// PatchWarden is an MCP stdio entrypoint, not a conventional --version CLI.
	// If the detector executes this stub, it would incorrectly report 9.9.9.
	mock.SetCommand("9.9.9\n", "", 0, bin, "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	for _, result := range results {
		if result.Name == "patchwarden" {
			if result.Version != "unknown" {
				t.Errorf("expected metadata-only version to remain unknown, got %s", result.Version)
			}
			return
		}
	}
	t.Fatal("patchwarden not found")
}

func TestAICLIDetector_FindsPatchWardenWindowsNPMShim(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS(model.PlatformWindows)
	shim := `C:\Users\testuser\AppData\Roaming\npm\patchwarden.cmd`
	pkgRoot := `C:\Users\testuser\AppData\Roaming\npm\node_modules\patchwarden`
	mock.SetPath("patchwarden", shim)
	mock.SetFile(shim, []byte(`"%_prog%" "%dp0%\node_modules\patchwarden\dist\index.js" %*`))
	mock.SetFile(pkgRoot+`\package.json`, []byte(`{"name":"patchwarden","version":"1.6.2"}`))

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	for _, result := range results {
		if result.Name != "patchwarden" {
			continue
		}
		if result.Version != "1.6.2" {
			t.Errorf("expected version 1.6.2 from Windows npm metadata, got %s", result.Version)
		}
		if result.InstallPath != pkgRoot {
			t.Errorf("expected install_path %s, got %s", pkgRoot, result.InstallPath)
		}
		if result.ConfigDir != "" {
			t.Errorf("expected no user-level config dir, got %s", result.ConfigDir)
		}
		return
	}
	t.Fatal("patchwarden not found via Windows npm shim")
}

func TestAICLIDetector_DoesNotTreatPatchWardenArtifactsAsInstallation(t *testing.T) {
	mock := executor.NewMock()
	mock.SetDir("/Users/testuser/.patchwarden")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	for _, result := range results {
		if result.Name == "patchwarden" {
			t.Fatalf("stale .patchwarden artifacts must not prove installation: %+v", result)
		}
	}
}

// TestAICLIDetector_ResolvesNpmInstallPath asserts that when the binary on
// PATH is a symlink to a node_modules package (the standard layout for
// claude-code, codex, opencode, etc.), the detector surfaces both the shim
// (binary_path) and the package root (install_path). See bug 0001.
func TestAICLIDetector_ResolvesNpmInstallPath(t *testing.T) {
	mock := executor.NewMock()
	shim := "/usr/local/bin/claude"
	target := "/usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe"
	pkgRoot := "/usr/local/lib/node_modules/@anthropic-ai/claude-code"
	mock.SetPath("claude", shim)
	mock.SetSymlink(shim, target)
	mock.SetCommand("2.1.117 (Claude Code)\n", "", 0, shim, "--version")
	mock.SetDir("/Users/testuser/.claude")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	var got *model.AITool
	for i, r := range results {
		if r.Name == "claude-code" {
			got = &results[i]
			break
		}
	}
	if got == nil {
		t.Fatal("claude-code not found")
	}
	if got.BinaryPath != shim {
		t.Errorf("expected binary_path %s, got %s", shim, got.BinaryPath)
	}
	if got.InstallPath != pkgRoot {
		t.Errorf("expected install_path %s (npm package root), got %s", pkgRoot, got.InstallPath)
	}
	if got.Version != "2.1.117" {
		t.Errorf("expected version 2.1.117 (extractVersionFromOutput should strip the suffix), got %s", got.Version)
	}
}

// TestAICLIDetector_NonSymlinkInstallPath asserts that when the PATH binary
// is not a symlink, install_path equals the binary path itself rather than
// being left empty.
func TestAICLIDetector_NonSymlinkInstallPath(t *testing.T) {
	mock := executor.NewMock()
	bin := "/usr/local/bin/aider"
	mock.SetPath("aider", bin)
	mock.SetCommand("aider 0.86.2\n", "", 0, bin, "--version")
	// No SetSymlink: EvalSymlinks returns the path unchanged.

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	var got *model.AITool
	for i, r := range results {
		if r.Name == "aider" {
			got = &results[i]
			break
		}
	}
	if got == nil {
		t.Fatal("aider not found")
	}
	if got.InstallPath != bin {
		t.Errorf("expected install_path %s (resolved real path == binary), got %s", bin, got.InstallPath)
	}
}

// TestAICLIDetector_ResolvesNpmShimOnWindows asserts that on Windows, where
// npm installs `.cmd` shims rather than symlinks, the detector still surfaces
// the node_modules package root as install_path by parsing the shim.
func TestAICLIDetector_ResolvesNpmShimOnWindows(t *testing.T) {
	mock := executor.NewMock()
	mock.SetGOOS("windows")
	shim := `C:\Users\Administrator\AppData\Roaming\npm\claude.cmd`
	mock.SetPath("claude", shim)
	// cmd-shim layout: the shim references node_modules\<scope>\<pkg>\cli.js
	// relative to its own directory (%dp0%).
	shimBody := `@ECHO off
GOTO start
:find_dp0
SET dp0=%~dp0
EXIT /b
:start
SETLOCAL
CALL :find_dp0

IF EXIST "%dp0%\node.exe" (
  SET "_prog=%dp0%\node.exe"
) ELSE (
  SET "_prog=node"
  SET PATHEXT=%PATHEXT:;.JS;=;%
)

endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\node_modules\@anthropic-ai\claude-code\cli.js" %*
`
	mock.SetFile(shim, []byte(shimBody))
	mock.SetCommand("2.1.98 (Claude Code)\n", "", 0, shim, "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	var got *model.AITool
	for i, r := range results {
		if r.Name == "claude-code" {
			got = &results[i]
			break
		}
	}
	if got == nil {
		t.Fatal("claude-code not found")
	}
	wantInstall := `C:\Users\Administrator\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code`
	if got.InstallPath != wantInstall {
		t.Errorf("expected install_path %s (parsed from .cmd shim), got %s", wantInstall, got.InstallPath)
	}
	if got.BinaryPath != shim {
		t.Errorf("expected binary_path %s, got %s", shim, got.BinaryPath)
	}
}

// TestExtractVersionFromOutput asserts that decorated `--version` output
// (notably ollama warnings emitted before the version line) still yields the
// real version. See bug 0001 F3.
func TestExtractVersionFromOutput(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		want   string
	}{
		{
			name:   "ollama warnings before version",
			stdout: "Warning: could not connect to a running Ollama instance\nWarning: client version is 0.0.0\n",
			want:   "0.0.0",
		},
		{
			name:   "single-line plain version",
			stdout: "0.5.4\n",
			want:   "0.5.4",
		},
		{
			name:   "tool-name prefix",
			stdout: "codex-cli 0.118.0\n",
			want:   "0.118.0",
		},
		{
			name:   "v-prefix preserved",
			stdout: "v1.2.3\n",
			want:   "v1.2.3",
		},
		{
			name:   "all-noise no version token",
			stdout: "Hello world\nGoodbye\n",
			want:   "unknown",
		},
		{
			name:   "empty",
			stdout: "",
			want:   "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractVersionFromOutput(tt.stdout); got != tt.want {
				t.Errorf("extractVersionFromOutput(%q) = %q, want %q", tt.stdout, got, tt.want)
			}
		})
	}
}

func TestAICLIDetector_FindsCursorAgentInLocalBin(t *testing.T) {
	// Binary is not on PATH, but the official installer's symlink at
	// ~/.local/bin/cursor-agent exists. The home-relative fallback should pick it up.
	homeBinPath := "/Users/testuser/.local/bin/cursor-agent"
	mock := executor.NewMock()
	mock.SetFile(homeBinPath, []byte{})
	mock.SetCommand("2026.02.27-e7d2ef6\n", "", 0, homeBinPath, "--version")
	mock.SetDir("/Users/testuser/.cursor")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	found := false
	for _, r := range results {
		if r.Name == "cursor-agent" {
			found = true
			if r.BinaryPath != homeBinPath {
				t.Errorf("expected %s, got %s", homeBinPath, r.BinaryPath)
			}
		}
	}
	if !found {
		t.Error("cursor-agent not found via ~/.local/bin fallback")
	}
}

// TestAICLIDetector_CursorAgentVersionFromMetadata is the regression test for
// the customer-reported Gatekeeper popup: executing cursor-agent dlopens an
// un-notarized native addon, so the version must come from the install
// layout's versions/<v>/ directory without launching the binary. No command
// stub is registered — if the detector exec'd anything, the mock would error
// and the version would degrade to "unknown".
func TestAICLIDetector_CursorAgentVersionFromMetadata(t *testing.T) {
	binary := "/Users/testuser/.local/bin/cursor-agent"
	mock := executor.NewMock()
	mock.SetPath("cursor-agent", binary)
	mock.SetSymlink(binary, "/Users/testuser/.local/share/cursor-agent/versions/2026.03.11-6dfa30c/cursor-agent")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	var got *model.AITool
	for i, r := range results {
		if r.Name == "cursor-agent" {
			got = &results[i]
			break
		}
	}
	if got == nil {
		t.Fatal("cursor-agent not found")
	}
	if got.Version != "2026.03.11-6dfa30c" {
		t.Errorf("expected version 2026.03.11-6dfa30c from metadata (no exec), got %s", got.Version)
	}
}

// TestAICLIDetector_VersionExecFallback pins the failsafe: when no metadata
// source exists, the detector still execs `--version` exactly as before.
func TestAICLIDetector_VersionExecFallback(t *testing.T) {
	binary := "/usr/local/bin/aider"
	mock := executor.NewMock()
	mock.SetPath("aider", binary)
	mock.SetCommand("aider 0.86.2\n", "", 0, binary, "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	for _, r := range results {
		if r.Name == "aider" {
			if r.Version != "0.86.2" {
				t.Errorf("expected exec-fallback version 0.86.2, got %s", r.Version)
			}
			return
		}
	}
	t.Fatal("aider not found")
}

// TestAICLIDetector_SkipsQuarantinedBinary pins the Gatekeeper pre-exec
// guard: a quarantined, spctl-rejected binary with no metadata version must
// NOT be executed for its version — executing it would pop the macOS "could
// not verify" dialog. The `--version` stub answers 9.9.9, so a regression
// that re-enables the exec would flip the asserted version off "unknown".
func TestAICLIDetector_SkipsQuarantinedBinary(t *testing.T) {
	binary := "/usr/local/bin/aider"
	mock := executor.NewMock()
	mock.SetPath("aider", binary)
	mock.SetCommand("0083;65a1b2c3;Safari;", "", 0, "/usr/bin/xattr", "-p", "com.apple.quarantine", binary)
	mock.SetCommand("", "rejected", 3, "/usr/sbin/spctl", "--assess", "--type", "execute", binary)
	mock.SetCommand("aider 9.9.9\n", "", 0, binary, "--version")

	det := NewAICLIDetector(mock)
	results := det.Detect(context.Background())

	for _, r := range results {
		if r.Name == "aider" {
			if r.Version != "unknown" {
				t.Errorf("expected version unknown (exec skipped by Gatekeeper guard), got %s", r.Version)
			}
			return
		}
	}
	t.Fatal("aider not found — the guard must skip the exec, not the tool")
}
