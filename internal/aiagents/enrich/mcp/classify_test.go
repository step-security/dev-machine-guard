package mcp

import (
	"context"
	"strings"
	"testing"
)

func TestClassifyShellMCPPackageIsLocal(t *testing.T) {
	info, _ := ClassifyShell(context.Background(), "npx -y @modelcontextprotocol/server-filesystem /tmp")
	if info == nil {
		t.Fatalf("expected detection")
	}
	if info.ServerName != "server-filesystem" {
		t.Errorf("server: %q", info.ServerName)
	}
	if info.Kind != "local" {
		t.Errorf("kind: %q", info.Kind)
	}
	if info.ServerCommand == "" {
		t.Errorf("expected redacted server_command snippet")
	}
}

func TestClassifyShellNonMCP(t *testing.T) {
	info, _ := ClassifyShell(context.Background(), "npm install lodash")
	if info != nil {
		t.Fatalf("expected nil, got %+v", info)
	}
}

// `claude mcp list` must be classified by the Claude-specific rule, not
// the generic ` mcp ` rule that would otherwise win on substring order.
// Both currently produce the same shape, but the ordering preserves
// future room to differentiate.
func TestClassifyShellClaudeMCPDetected(t *testing.T) {
	info, _ := ClassifyShell(context.Background(), "claude mcp list")
	if info == nil {
		t.Fatalf("expected detection")
	}
	if info.Kind != "unknown" {
		t.Errorf("kind: %q", info.Kind)
	}
}

// Bare `mcp ...` falls through to the generic rule but stays detected.
func TestClassifyShellGenericMCPDetected(t *testing.T) {
	info, _ := ClassifyShell(context.Background(), "mcp foo")
	if info == nil {
		t.Fatalf("expected detection")
	}
}

// ServerCommand must be redacted before storage so a token in a
// pre-command env assignment never lands on disk.
func TestClassifyShellRedactsServerCommand(t *testing.T) {
	cmd := "GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa npx -y @modelcontextprotocol/server-github"
	info, _ := ClassifyShell(context.Background(), cmd)
	if info == nil {
		t.Fatalf("expected detection")
	}
	if strings.Contains(info.ServerCommand, "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
		t.Errorf("server_command not redacted: %q", info.ServerCommand)
	}
}
