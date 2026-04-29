package detector

import (
	"context"
	"testing"

	"github.com/step-security/dev-machine-guard/internal/executor"
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
