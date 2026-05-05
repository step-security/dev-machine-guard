// Package aiagents is the root of the AI coding agent hooks domain.
//
// Subpackages own hook install/uninstall flows, the hidden runtime invoked
// by agents on each hook event, policy evaluation, telemetry upload, and
// the per-agent adapters (Claude Code, Codex). Phase 1 ships audit-mode
// only; the policy evaluator never returns a block decision to the agent.
//
// See docs/plans/ai-agent-hooks-port-plan.md for the full design.
package aiagents
