// Package mcp classifies MCP-related shell-launched activity.
//
// Direct mcp__<server>__<tool> tool events, MCP permission events, and
// Elicitation hooks already carry the server identity in top-level
// fields or the payload — no enrichment is produced for them. This
// package exists for the one case where the MCP signal is hidden
// inside a Bash command (e.g. `npx -y @modelcontextprotocol/server-foo`
// or `claude mcp ...`).
package mcp

import (
	"context"
	"errors"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
	"github.com/step-security/dev-machine-guard/internal/aiagents/redact"
)

// serverCommandCap bounds the redacted command snippet copied into
// MCPInfo.ServerCommand. The full command also lives on
// Enrichments.Shell.Command; this is a tighter projection for MCP
// joins, not a duplicate transport.
const serverCommandCap = 512

// ClassifyShell inspects a shell command for MCP-related invocations
// (e.g. `claude mcp ...`, `npx -y @modelcontextprotocol/server-foo`).
// Returns nil when no MCP signal is found.
//
// Branches are ordered so the most specific signal wins: `claude mcp`
// is checked before the generic `mcp` subcommand token, and the
// @modelcontextprotocol/ package before either.
func ClassifyShell(ctx context.Context, cmd string) (*event.MCPInfo, bool) {
	if isCtxCanceled(ctx) {
		return nil, true
	}
	lower := strings.ToLower(cmd)
	switch {
	case strings.Contains(lower, "@modelcontextprotocol/"):
		info := &event.MCPInfo{
			Kind:          "local",
			ServerCommand: redactedSnippet(cmd),
		}
		if name := extractMCPServerName(lower); name != "" {
			info.ServerName = name
		}
		return info, false
	case strings.Contains(lower, "claude mcp"):
		return &event.MCPInfo{
			Kind:          "unknown",
			ServerCommand: redactedSnippet(cmd),
		}, false
	case strings.Contains(lower, " mcp ") || strings.HasPrefix(lower, "mcp "):
		return &event.MCPInfo{
			Kind:          "unknown",
			ServerCommand: redactedSnippet(cmd),
		}, false
	}
	return nil, false
}

func extractMCPServerName(cmd string) string {
	const marker = "@modelcontextprotocol/"
	_, rest, ok := strings.Cut(cmd, marker)
	if !ok {
		return ""
	}
	for i, r := range rest {
		if r == ' ' || r == '\t' || r == '@' || r == ',' {
			return rest[:i]
		}
	}
	return rest
}

func redactedSnippet(cmd string) string {
	s := redact.String(cmd)
	if len(s) > serverCommandCap {
		return s[:serverCommandCap]
	}
	return s
}

func isCtxCanceled(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return errors.Is(ctx.Err(), context.DeadlineExceeded)
	default:
		return false
	}
}
