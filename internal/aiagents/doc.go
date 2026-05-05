// Package aiagents is the root of the AI coding agent hooks domain.
//
// Subpackages own hook install/uninstall flows, the hidden runtime invoked
// by agents on each hook event, policy evaluation, telemetry upload, and
// the per-agent adapters (Claude Code, Codex). The policy evaluator
// currently runs audit-mode only and never returns a block decision to
// the agent.
package aiagents
