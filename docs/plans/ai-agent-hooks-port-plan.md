# AI Agent Hooks Port Implementation Plan

**Goal:** Port Anchor's hook install / runtime / audit pipeline into `dev-machine-guard` for Claude Code and Codex. Audit-mode-only in phase 1, with the full policy evaluator ported in dormant form so block-mode can be flipped on later without code changes.

**Architecture:** New domain `internal/aiagents/...` housing every hook-specific package. The hot-path runtime and CLI install/uninstall flows are net-new code; identity, config, executor, and buildinfo are reused from existing DMG packages with **no DMG code modifications** (other than CLI parser dispatch in `internal/cli/cli.go` and the main wire-up in `cmd/stepsecurity-dev-machine-guard/main.go`).

**Tech Stack:** Go 1.24 (no version bump). Hand-rolled CLI parser extended in place — no cobra. Anchor's third-party dependencies imported as-is except cobra.

Anchor's source code directory: /Users/subhamray/workspace/anchor

---

## 1. Confirmed Decisions

### 1.1 CLI surface

- New top-level group: `stepsecurity-dev-machine-guard hooks <install|uninstall> [--agent <name>]`.
- New hidden runtime: `stepsecurity-dev-machine-guard _hook <agent> <hookEvent>`.
- Existing top-level `install` / `uninstall` (scheduler) are untouched.
- Supported agents in phase 1: `claude-code`, `codex`.
- Only flag on hooks subcommands: `--agent <name>`. No `--force`. No `--dry-run`.
- DMG global flags (`--pretty`, `--json`, `--html`, `--enable-*-scan`, `--search-dirs`, etc.) are **rejected** on hooks subcommands.

### 1.2 Detection and install scope

- **Detection criterion:** the agent's binary is resolvable on `$PATH` via `executor.LookPath`.
  - `claude-code` ⇢ `claude`
  - `codex` ⇢ `codex`
- Default flow (no `--agent`): install for every detected agent.
- `--agent <name>` overrides detection: install for that agent unconditionally.
- **Settings file is created from scratch when absent.** When present, install is idempotent — add hooks if missing, no-op if already present.

### 1.3 Hook command shape

- The command written into agent settings uses the **absolute path** to the DMG binary, resolved at install time via `os.Executable` + `filepath.EvalSymlinks`.
- Format: `<abs-path>/stepsecurity-dev-machine-guard _hook <agent> <hookEvent>`.
- No auto-heal on binary move. If the binary moves (e.g., `brew upgrade` relocates it), hooks silently break until the user reruns `hooks install`. Documented in user-facing docs as a known follow-up.

### 1.4 Owned-hook matching for uninstall

- Uninstall removes only entries whose `command` field matches the literal regex `(^|/)stepsecurity-dev-machine-guard\s+_hook\s+`.
- Tolerates: any absolute path basename (covers prior install locations).
- Does not remove: bare `anchor _hook ...` legacy entries, third-party hooks, anything not invoking the DMG binary.

### 1.5 Logged-in user resolution

- All install operations go through DMG's `executor.LoggedInUser()`.
- When running as root and no console user is found:
  - log a structured entry to `~/.stepsecurity/ai-agent-hook-errors.jsonl`
  - write a one-line note to `stderr`
  - exit `0`
- When running as a normal user, target `os.UserHomeDir()` (the calling user) directly.
- Multi-user machines: install only for the current console user. Other users are not touched.

### 1.6 File ownership under root install

- When root install resolves a console user, every file written or created (`~/.claude/settings.json`, `~/.codex/hooks.json`, `~/.codex/config.toml`, all `.dmg-backup.*` files, parent directories created during install) is `chown`-ed to that user's UID/GID after the atomic rename completes.
- Chown failures are logged to errors.jsonl but do not abort install (best-effort; an unchown'd file is still a working install).

### 1.7 Identity

- AI-event identity is computed by a thin shim (`internal/aiagents/identity`) that calls DMG's `device.Gather(ctx, exec)`.
- Context is bounded to **1 second**. On timeout, the shim returns whatever DMG returned partially; missing values stay as `"unknown"` — no rewrite to empty string.
- Wire-format field is **`device_id`**, sourced from `device.Device.SerialNumber`.
- Wire-format field `user_identity` is sourced from `device.Device.UserIdentity`.
- No identity caching across hook invocations (each hook is a fresh process).
- **No modifications to `internal/device/`.**

### 1.8 Config

- Reuse DMG's existing `internal/config` package. The hook runtime reads `config.CustomerID`, `config.APIEndpoint`, `config.APIKey` after calling `config.Load()`.
- Enterprise check uses **a stricter local helper** in `internal/aiagents/ingest`: all three fields must be non-empty and non-placeholder. (DMG's `config.IsEnterpriseMode()` checks only `APIKey` — too lax for the upload path.)
- `hooks install` calls the same stricter check up front and refuses to proceed when enterprise config is incomplete.
- Per-user `~/.stepsecurity/config.json` is the only credential source. No `/etc/stepsecurity/config.json` fallback. (MDM provisioning of per-user config is DMG's existing responsibility.)

### 1.9 Policy

- Port the full Anchor policy evaluator: `policy/{policy,decision,ecosystem,eval,bypass}.go` plus `builtin/policy.json`.
- Policy mode is forced to `audit` regardless of what the embedded JSON says — phase 1 never returns a block decision to the agent. Audit emits `policy_decision.would_block=true` on violations.
- The embedded `builtin/policy.json` allowlist is kept as-is (`https://registry.stepsecurity.io/`) — it will be replaced by an API-fetched policy later, and audit-mode emissions are not customer-visible noise.
- All enrichment paths (`enrich/npm`, `enrich/mcp`, `enrich/secrets`) are ported in full.

### 1.10 Persistence

- **No `events.jsonl`.** The Anchor `persist()` and `persistMinimal()` calls are removed from the ported runtime, not just made no-op.
- Upload failures are logged to `~/.stepsecurity/ai-agent-hook-errors.jsonl` with `event_id` for correlation; the event itself is dropped.
- The errors log is append-only, no advisory locks.
- **Truncate-and-restart at 5 MiB**: before each append, stat the file; if size > 5 MiB, truncate to zero and write the new entry.

### 1.11 Schema and wire format

- Event `schema_version` field is `ai_agent.event/v1` (renamed from `anchor.event/v1`).
- Upload endpoint: `POST <api_endpoint>/v1/{customer_id}/ai-agents/events`.
- HTTP `User-Agent`: `dev-machine-guard/<version>` sourced from `internal/buildinfo`.
- Same `api_endpoint` value as DMG's existing scan telemetry — no new config field.
- Upload timeout: 5 seconds (preserve Anchor's `DefaultHookUploadTimeout`).
- Hook total cap: **15 seconds** (was 10s in Anchor — bumped to absorb the 1s identity probe under load).

### 1.12 Errors log

- Path: `~/.stepsecurity/ai-agent-hook-errors.jsonl`.
- Format: JSONL, one entry per error: `{ts, stage, code, message, event_id?}`.
- Created with mode `0600`, parent dir `~/.stepsecurity/` is reused (already exists for DMG).
- All error messages run through `redact.String()` before write.

### 1.13 Backup naming and atomic writes

- Backup suffix: `.dmg-backup.<UTC stamp>` where stamp is `20060102T150405`.
- Atomic-write discipline preserved from Anchor (`atomicfile` package): write temp → fsync → close → chmod → rename → chown (under root).

### 1.14 Branding rebrand

- All `anchor` literals rebranded to `dev-machine-guard` (or the binary basename) across:
  - hook command prefix
  - JSON metadata (none today, confirm)
  - directory paths (none — error log is at the new top-level path, no `~/.stepsecurity/anchor/` subdir)
  - log messages, error wrapping, doc comments
- User-visible deny message (used only when block mode is later enabled): `"Blocked by your organization's administrator."`
- HTTP `User-Agent` rebranded.
- The `debugDumpCurl` function in `ingest/client.go` is **deleted** (not commented out, not gated by env var).

### 1.15 Codex install side effects

- Install sets `[features].codex_hooks = true` in `~/.codex/config.toml`.
- Uninstall does **not** revert the flag (matches Anchor; documented in user-facing docs).

### 1.16 Concurrency

- Deferred to a future revision. Phase 1 accepts:
  - concurrent fresh TCP+TLS handshakes per hook invocation (one per process)
  - concurrent appends to errors.jsonl without locks (entries < 4 KiB are atomic on POSIX `O_APPEND` writes)

---

## 2. Directory Layout

```
internal/aiagents/
  adapter/
    adapter.go                     # Adapter interface + Decision/Result types
    claudecode/
      adapter.go
      hooks.go                     # supportedHookEvents
      parse.go
      settings.go                  # JSON edits via tidwall/{gjson,sjson,pretty}
    codex/
      adapter.go
      hooks.go
      parse.go
      settings.go                  # hooks.json (JSON) + config.toml (pelletier/go-toml)
  hook/
    runtime.go                     # bounded fail-open hot path (no events.jsonl persist)
    stdin.go                       # 5 MiB cap
    policy.go                      # phase gate for policy evaluation
  event/
    event.go                       # schema_version = "ai_agent.event/v1"
  enrich/
    npm/
    mcp/
    secrets/
  policy/
    policy.go
    decision.go
    ecosystem.go
    eval.go
    bypass.go                      # uses google/shlex
    builtin/
      policy.json                  # embedded allowlist
  ingest/
    client.go                      # POST /v1/{customer_id}/ai-agents/events; no debugDumpCurl
  redact/
    redact.go
  configedit/
    json.go
    toml.go
  atomicfile/
    atomicfile.go                  # backup suffix .dmg-backup.<UTC>
  identity/
    identity.go                    # thin shim → device.Gather, returns Info{CustomerID,DeviceID,UserIdentity}
  cli/
    install.go                     # hooks install handler
    uninstall.go                   # hooks uninstall handler
    hook.go                        # _hook hidden runtime handler
    detect.go                      # adapterForAgent + selectAdapters
    errlog.go                      # ~/.stepsecurity/ai-agent-hook-errors.jsonl appender
    rootuser.go                    # logged-in user resolution + chown helper
    selfpath.go                    # os.Executable + EvalSymlinks
```

**DMG packages reused without modification:** `internal/config`, `internal/device`, `internal/executor`, `internal/buildinfo`.

**DMG packages modified:** `internal/cli/cli.go` (new dispatch arms), `cmd/stepsecurity-dev-machine-guard/main.go` (route to new dispatch).

---

## 3. Anchor Package Port Matrix

### Port (verbatim, with rename pass)

| Anchor package | Destination | Notes |
|---|---|---|
| `internal/adapter` | `internal/aiagents/adapter` | |
| `internal/adapter/claudecode` | `internal/aiagents/adapter/claudecode` | rebrand strings |
| `internal/adapter/codex` | `internal/aiagents/adapter/codex` | rebrand strings + config.toml side effect docs |
| `internal/hook` | `internal/aiagents/hook` | drop `persist`, drop `persistMinimal` writes |
| `internal/event` | `internal/aiagents/event` | `schema_version` rename |
| `internal/enrich/{npm,mcp,secrets}` | `internal/aiagents/enrich/...` | |
| `internal/policy` | `internal/aiagents/policy` | force `Mode=audit` at evaluation site |
| `internal/ingest` | `internal/aiagents/ingest` | delete `debugDumpCurl`, change UA, change endpoint URL stays |
| `internal/redact` | `internal/aiagents/redact` | |
| `internal/configedit` | `internal/aiagents/configedit` | |
| `internal/atomicfile` | `internal/aiagents/atomicfile` | backup suffix `.dmg-backup.` |

### Reuse from DMG (do not port)

| Anchor package | DMG equivalent |
|---|---|
| `internal/config` | `internal/config` (with stricter enterprise check in ingest) |
| `internal/identity` | `internal/device` via thin shim in `internal/aiagents/identity` |
| `internal/paths` | inlined in `internal/aiagents/cli` (paths are short and few) |
| `internal/version` | `internal/buildinfo` |
| `internal/jsonl` | not needed (no events.jsonl) |
| `internal/logging` | inlined as `internal/aiagents/cli/errlog.go` |
| `cmd/anchor` | `cmd/stepsecurity-dev-machine-guard/main.go` extension |
| `internal/cli/{install,uninstall,hook}` | rewritten in `internal/aiagents/cli/...` |

### Do not port

- `internal/registryconf` — dormant (`//go:build dormant`), responsibility moved out of Anchor, not in roadmap.
- `internal/logtail` — only used by `anchor logs`, not shipping.
- `internal/cli/{logs,restore,status,doctor,root}` — not shipping those commands.
- Anchor's adapter `Restore()` and `Status()` methods — drop from interface.

---

## 4. Third-Party Dependencies Added

Phase 1 adds the following to `go.mod`:

| Module | Purpose |
|---|---|
| `github.com/tidwall/gjson` | read-only JSON path queries on settings files |
| `github.com/tidwall/sjson` | minimally-invasive JSON edits preserving user formatting |
| `github.com/tidwall/pretty` | post-edit pretty-printing |
| `github.com/tidwall/match` | indirect (gjson dep) |
| `github.com/pelletier/go-toml/v2` | Codex `config.toml` parsing/encoding |
| `github.com/google/shlex` | shell tokenization for policy bypass parser |
| `gopkg.in/yaml.v3` | only if any ported file imports it; verify and drop if unused |

**Not added:**

- `github.com/spf13/cobra` (we extend the hand-rolled parser)
- `github.com/spf13/pflag` (cobra transitive)
- `github.com/inconshreveable/mousetrap` (cobra transitive)

---

## 5. Phased Execution Plan

### Phase 0 — Foundation and Guardrails

Net-new infrastructure. No agent integration yet.

**Tickets:**

| # | Title | Files | Acceptance |
|---|---|---|---|
| 0.1 | CLI parser dispatch for `hooks` group | `internal/cli/cli.go`, `internal/cli/cli_test.go` | `hooks install`, `hooks uninstall`, `_hook <agent> <event>` parse correctly; unknown subcommands error; DMG global flags rejected on hooks subcommands |
| 0.2 | Self-path resolver | `internal/aiagents/cli/selfpath.go` (+ test) | `Resolve()` returns absolute path with symlinks evaluated; works on Mac, Linux, Windows; documented behavior under `brew` symlinks |
| 0.3 | Errors log appender | `internal/aiagents/cli/errlog.go` (+ test) | Append a JSONL entry; create file mode 0600; truncate-and-restart at 5 MiB; redact message via `redact.String` |
| 0.4 | Logged-in user + chown helper | `internal/aiagents/cli/rootuser.go` (+ test with executor stub) | Resolve console user via `executor.LoggedInUser`; on root + no user, log + stderr + exit 0; chown helper that walks file + parents to UID/GID, best-effort |
| 0.5 | Identity shim | `internal/aiagents/identity/identity.go` (+ test) | Returns `Info{CustomerID, DeviceID, UserIdentity}`; calls `device.Gather` with 1s context; passes "unknown" through; field `device_id` sourced from `SerialNumber` |
| 0.6 | Stricter enterprise-config check | `internal/aiagents/ingest/config.go` (+ test) | Returns `(Config, true)` only when all three credential fields are non-empty and contain no `{{...}}` placeholders |
| 0.7 | Atomic file + backup suffix | `internal/aiagents/atomicfile/atomicfile.go` (+ test) | Backup suffix `.dmg-backup.<UTC>`; preserves Anchor's atomic write discipline; chown hook for caller |
| 0.8 | Wire `cmd/main.go` to new dispatch | `cmd/stepsecurity-dev-machine-guard/main.go` | `hooks install` (placeholder handler) returns no-op; `_hook` is hidden from help; existing flows unchanged |

**Phase 0 exit criteria:**

- All existing DMG tests still pass.
- `go vet ./...` and `go build ./...` clean.
- `stepsecurity-dev-machine-guard hooks install --help` shows new help.
- `stepsecurity-dev-machine-guard install` (scheduler) behavior is byte-identical.

### Phase 1 — Adapters (Claude Code + Codex)

Ports detection, install, uninstall mutation logic. No hot-path runtime yet.

**Tickets:**

| # | Title | Files | Acceptance |
|---|---|---|---|
| 1.1 | Adapter interface (trimmed) | `internal/aiagents/adapter/adapter.go` | Drops `Restore`, `Status`, `RestoreOptions`, `BackupInfo`, `HookStatus` from Anchor's interface; keeps `Detect`, `Install`, `Uninstall`, `ParseEvent`, `ShellCommand`, `DecideResponse`, `SupportedHooks`, `ManagedFiles`, `Name` |
| 1.2 | configedit port | `internal/aiagents/configedit/{json,toml}.go` | All Anchor configedit tests pass after rename |
| 1.3 | Claude Code adapter | `internal/aiagents/adapter/claudecode/{adapter,hooks,settings,parse}.go` | All Anchor claudecode tests pass; install command uses absolute DMG binary path; uninstall matcher matches new path shape |
| 1.4 | Codex adapter | `internal/aiagents/adapter/codex/{adapter,hooks,settings,parse}.go` | All Anchor codex tests pass; install writes hooks.json + sets `[features].codex_hooks=true`; load-validate-encode both files before writing either; uninstall removes hooks but leaves flag |
| 1.5 | Detection criterion change | `internal/aiagents/cli/detect.go` (+ test) | `Detect()` reports `Detected=true` when `executor.LookPath("claude")` (Claude) or `executor.LookPath("codex")` (Codex) succeeds; settings file existence is no longer the gate |
| 1.6 | `hooks install` handler | `internal/aiagents/cli/install.go` (+ test) | Validates enterprise config; resolves binary path; selects adapters per detection or `--agent`; runs adapter Install; under root, chowns outputs to console user; emits user-friendly summary |
| 1.7 | `hooks uninstall` handler | `internal/aiagents/cli/uninstall.go` (+ test) | Selects adapters per detection or `--agent`; runs adapter Uninstall; never deletes the settings file even when empty |
| 1.8 | Branding sweep (adapters layer) | all of the above | No string `anchor` remains in the new packages; deny message text is `Blocked by your organization's administrator.` |

**Phase 1 exit criteria:**

- `hooks install --agent claude-code` writes a valid hook block whether or not `~/.claude/settings.json` previously existed.
- `hooks install` (no flag) installs only for agents whose binary is on `$PATH`.
- `hooks uninstall` removes only DMG-owned entries; user-authored hooks survive.
- Backup files use `.dmg-backup.<UTC>` suffix.
- Under `sudo`, files in the console user's home are owned by that user after install.
- All ported adapter tests pass.

### Phase 2 — Hidden Hook Runtime + Event Pipeline

Wires the hot path. No backend upload yet.

**Tickets:**

| # | Title | Files | Acceptance |
|---|---|---|---|
| 2.1 | event package | `internal/aiagents/event/event.go` (+ test) | `SchemaVersion = "ai_agent.event/v1"`; all Anchor event tests pass after rename |
| 2.2 | redact port | `internal/aiagents/redact/redact.go` (+ test) | All Anchor redact tests pass |
| 2.3 | enrich/npm | `internal/aiagents/enrich/npm/...` (+ test) | All Anchor npm enrichment tests pass |
| 2.4 | enrich/mcp | `internal/aiagents/enrich/mcp/...` (+ test) | All Anchor mcp tests pass |
| 2.5 | enrich/secrets | `internal/aiagents/enrich/secrets/...` (+ test) | All Anchor secrets tests pass |
| 2.6 | policy port (audit-locked) | `internal/aiagents/policy/...` (+ test) | All Anchor policy tests pass; Mode is forced to audit at evaluation site so block decisions never escape |
| 2.7 | hook runtime | `internal/aiagents/hook/{runtime,stdin,policy}.go` (+ test) | Bounded stdin (5 MiB); fail-open on every error; classify → enrich → policy (audit) → upload (stub) → emit response; cap raised to 15s; `persist`/`persistMinimal` calls removed |
| 2.8 | `_hook` handler wires runtime | `internal/aiagents/cli/hook.go` (+ test) | Resolves adapter; runs `Runtime.Run`; swallows error; exit 0 |

**Phase 2 exit criteria:**

- Pipe a known Claude PreToolUse payload into `_hook claude-code PreToolUse`; runtime emits a valid allow response on stdout in under 1s on warm cache.
- Pipe a malformed payload; runtime still emits allow.
- No `events.jsonl` is written under any circumstance.
- Hook errors land in `~/.stepsecurity/ai-agent-hook-errors.jsonl`.

### Phase 3 — Telemetry Upload

Connects the hot path to the AI-agents endpoint.

**Tickets:**

| # | Title | Files | Acceptance |
|---|---|---|---|
| 3.1 | ingest client port | `internal/aiagents/ingest/client.go` (+ test) | POST to `<api_endpoint>/v1/{customer_id}/ai-agents/events`; UA `dev-machine-guard/<version>`; no `debugDumpCurl`; treats 200/201/202/409 as success |
| 3.2 | enterprise config gate | `internal/aiagents/ingest/config.go` | Stricter check from 0.6 wired to `Client.New`; missing creds → no client constructed → no upload attempted |
| 3.3 | Runtime wires upload | `internal/aiagents/hook/runtime.go` | `resolveUpload` returns nil when not enterprise-configured; upload errors logged to errors.jsonl with event_id; allow response still emitted |
| 3.4 | install enterprise-required gate | `internal/aiagents/cli/install.go` | `hooks install` exits non-zero with a clear message if enterprise config is incomplete |

**Phase 3 exit criteria:**

- With valid enterprise config, a hook invocation results in a real POST to the AI-agents endpoint within the 5s upload cap.
- Without enterprise config, `hooks install` refuses; `_hook` runtime is silent (no upload attempted, no error logged for the missing config alone).
- A simulated 5xx upload causes an errors.jsonl line with the event_id and a user-visible allow response.
- No plaintext credentials in any on-disk file.

### Phase 4 — Test, Docs, Release Hardening

| # | Title |
|---|---|
| 4.1 | Cross-platform smoke tests for self-path resolution (Mac symlinked binary, Linux direct, Windows .exe) |
| 4.2 | Smoke test: install → invoke → uninstall on a temp `$HOME` |
| 4.3 | Concurrent-hook stress test (best effort, mark perf-sensitive) |
| 4.4 | README section on `hooks install` UX |
| 4.5 | Enterprise mode docs: audit-only positioning, complementary-to-EDR/MDM language |
| 4.6 | Document Codex `[features].codex_hooks=true` residue and binary-move-breaks-hooks caveat |
| 4.7 | CHANGELOG entry |

---

## 6. Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Binary move silently breaks hooks (absolute path) | Documented; user reruns `hooks install`. Future: post-upgrade hook in install scripts. |
| Embedded policy allowlist mismatches customer registry | Audit-mode in phase 1 — `would_block` signal is informational only. API-fetched policy planned. |
| Identity probe under load exceeds 1s and reports `unknown` | 15s hook cap absorbs occasional `unknown` device_ids; not a correctness issue, only telemetry quality. |
| Concurrent appends to errors.jsonl interleave | Phase 1 tolerates rare interleave; future revision moves to per-process tempfile + rename. |
| Backend strict-checks `schema_version` and rejects `ai_agent.event/v1` | Confirmed: backend accepts arbitrary schema_version values. |
| Cobra-style flag parsing implicitly assumed somewhere in port | Hand-rolled extension covers `hooks <verb>` + positional `_hook <agent> <event>` only — minimal new parser surface. Tests in 0.1 enforce. |
| Codex `[features].codex_hooks=true` left enabled after uninstall confuses users | Documented in 4.6; matches Anchor behavior. |
| `chown` failures under root install | Best-effort; logged but non-fatal; install reports a warning note. |
| `debugDumpCurl` accidentally retained | Hard-deleted in 3.1; CI grep check in 4.1 to prevent reintroduction. |

---

## 7. Scope Control Checklist

- [ ] No `internal/registryconf` files imported, recreated, or referenced.
- [ ] No `internal/logtail` imported.
- [ ] No `logs`, `restore`, `status`, `doctor` subcommands added.
- [ ] No `events.jsonl` written under any code path.
- [ ] No block-mode response shape returned to the agent in phase 1 (force audit at policy evaluation site).
- [ ] No backwards-compat migration of pre-existing `anchor _hook ...` entries.
- [ ] No `--force`, no `--dry-run` flag.
- [ ] No `cobra`, no `pflag`, no `mousetrap` in `go.mod`.
- [ ] No Go toolchain bump (stays on 1.24).
- [ ] No modifications to `internal/device`, `internal/config`, `internal/executor`, `internal/buildinfo`.
- [ ] No `/etc/stepsecurity/config.json` system-wide config fallback.
- [ ] No `debugDumpCurl` or any plaintext credential dump.
- [ ] No literal `anchor` strings in shipped code (greppable check).
- [ ] No identity caching across hook invocations.

---

## 8. Open Items / Future Work

- Block-mode flip (planned within weeks): force-audit gate in `policy/eval.go` evaluation site removed; no other code change needed.
- API-fetched policy: replace embedded `builtin/policy.json` with a fetch from the StepSecurity backend.
- Async upload sidecar: today's hot-path cold-handshake cost is the largest perf surface. A per-user sidecar daemon with Unix socket coalescing eliminates it without changing the hook runtime contract.
- Auto-heal on binary move: post-upgrade hook in install scripts that reruns `hooks install`.
- `hooks status` / `hooks restore`: deferred until block mode lands and customers ask.
- Multi-user install under root (install for all users, not just console user): deferred.
