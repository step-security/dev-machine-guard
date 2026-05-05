# AI Agent Hooks Migration Backlog

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans or a normal code-review workflow before implementing these items. These are deferred migration-hardening issues, not blockers for the current phase.

**Goal:** Track post-migration hardening items found during the Phase 1 review so they can be addressed after the full Anchor-to-DMG port is complete.

**Context:** Phase 1 adapter tests, `go test ./...`, `go build ./...`, and `go vet ./...` passed at review time. The items below are intentionally backlogged to avoid disrupting ongoing migration work.

---

## Backlog Items

### 1. Align sudo install with console-user config loading

**Current behavior:** `config.Load()` runs before hook install dispatch and reads config relative to the process home. Under `sudo`, this can read root's config instead of the console user's per-user config.

**Relevant files:**
- `cmd/stepsecurity-dev-machine-guard/main.go`
- `internal/aiagents/cli/install.go`
- `internal/config/config.go`

**Future acceptance:**
- `sudo stepsecurity-dev-machine-guard hooks install` validates the console user's `~/.stepsecurity/config.json`.
- Missing root config does not block hook install when the console user has valid enterprise config.
- Existing scheduler `install` behavior remains unchanged.

### 2. Improve root console-user resolution beyond macOS

**Current behavior:** `executor.Real.LoggedInUser()` falls back to `CurrentUser()` outside macOS, so root on Linux resolves as root and hook install exits as a no-op.

**Relevant files:**
- `internal/executor/executor.go`
- `internal/aiagents/cli/rootuser.go`
- `internal/aiagents/cli/rootuser_test.go`

**Future acceptance:**
- Root installs on supported OSes either resolve the intended interactive user or emit a clear no-op diagnostic.
- Phase 1 ownership guarantee is verified for every supported sudo path.

### 3. Chown partial adapter writes after install errors

**Current behavior:** If Codex writes `hooks.json` and then fails while writing `config.toml`, `RunInstall` skips chown for the partial result.

**Relevant files:**
- `internal/aiagents/cli/install.go`
- `internal/aiagents/adapter/codex/adapter.go`

**Future acceptance:**
- Any file or backup successfully written before an adapter error is still chowned best-effort under root.
- The install command still exits non-zero on the adapter error.

### 4. Shell-quote hook command binary paths

**Current behavior:** Hook commands are built by raw string concatenation. A binary path containing spaces or shell metacharacters may not execute correctly.

**Relevant files:**
- `internal/aiagents/adapter/claudecode/adapter.go`
- `internal/aiagents/adapter/codex/adapter.go`
- Adapter install tests for both agents.

**Future acceptance:**
- Binary paths containing spaces are safely represented in Claude Code and Codex hook command strings.
- Uninstall matching still removes DMG-owned entries after quoting is introduced.

### 5. Revisit atomic-file permissions

**Current behavior:** `PickMode` preserves broad existing modes, and newly created parent directories use `0755`. Anchor used tighter behavior for sensitive config paths.

**Relevant files:**
- `internal/aiagents/atomicfile/atomicfile.go`
- `internal/aiagents/atomicfile/atomicfile_test.go`
- Claude/Codex settings write tests.

**Future acceptance:**
- Fresh settings files remain `0600`.
- Fresh parent config directories use the intended private mode.
- Existing tighter modes stay tight, while overly broad modes are not preserved unless explicitly desired.

### 6. Narrow DMG-owned hook matching

**Current behavior:** The managed-hook regex can match `stepsecurity-dev-machine-guard _hook` inside a larger shell command argument, not only as the executable token.

**Relevant files:**
- `internal/aiagents/adapter/claudecode/settings.go`
- `internal/aiagents/adapter/codex/settings.go`
- Claude/Codex uninstall tests.

**Future acceptance:**
- User-authored hooks survive when the DMG hook string appears as data or an argument.
- DMG-owned absolute-path hook commands are still removed.
- Legacy `anchor _hook ...` entries are still left untouched.

### 7. Move stale Claude managed hooks to wildcard matcher

**Current behavior:** Claude install refreshes a managed hook found under a stale matcher, but does not necessarily move it to matcher `*`.

**Relevant files:**
- `internal/aiagents/adapter/claudecode/settings.go`
- `internal/aiagents/adapter/claudecode/adapter_test.go`

**Future acceptance:**
- Pre-existing DMG-owned Claude hooks under narrow matchers are moved or recreated under matcher `*`.
- Duplicate stale managed entries are collapsed without removing user-authored hooks.

### 8. Decide how strict the branding grep should be

**Current behavior:** Runtime strings appear rebranded, but comments and test fixtures still include `anchor` to document legacy entries that must not be removed.

**Relevant files:**
- `internal/aiagents/adapter/adapter.go`
- `internal/aiagents/adapter/claudecode/adapter_test.go`
- `internal/aiagents/adapter/codex/adapter_test.go`
- `internal/aiagents/adapter/*/settings.go`

**Future acceptance:**
- If CI uses a literal grep, comments/fixtures are rewritten or the grep is scoped to shipped user-visible strings.
- Tests continue to assert legacy `anchor _hook ...` entries are not migrated or removed.

---

## Review Commands Used

```bash
go test ./internal/aiagents/... ./internal/cli ./cmd/stepsecurity-dev-machine-guard
go test ./...
go build ./...
go vet ./...
```

All commands passed during the Phase 1 review.
