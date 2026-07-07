# Dev Machine Guard — Coding Guidelines

These guidelines describe **how this codebase is already written**, distilled into rules so
future work stays consistent. They are descriptive, not aspirational: every rule below is the
*dominant existing pattern*, with a canonical file you can copy from.

**Audience:** humans and AI agents making changes in this repo.

**How to use this doc.** Before adding a detector, a model field, a CLI flag, a scheduler tweak,
or any platform-specific code, find the matching section and follow the pattern. When in doubt,
open the cited "canonical" file and mirror it. Prefer consistency with the surrounding code over
personal preference.

**Scope.** This documents current conventions. It does **not** propose refactors. Genuinely
additive improvement ideas surfaced during analysis are quarantined in
[§17](#17-additive-improvement-backlog-future--not-part-of-these-guidelines) and are explicitly
*not* things to apply as part of adopting this doc.

> See also: [CONTRIBUTING.md](../CONTRIBUTING.md) · [adding-detections.md](adding-detections.md) ·
> [SCAN_COVERAGE.md](../SCAN_COVERAGE.md)

---

## 0. Prime directives

The ten rules that matter most. The rest of the doc expands on these.

1. **All OS interaction goes through `executor.Executor`.** Never call `os/exec`, and avoid raw
   `os.*` file/env access, in detector/scheduler/business logic. This is the seam that makes
   everything mockable and timeout-bounded. (§2.1, §7.1)
2. **A scan never aborts because one part failed.** Inventory detectors return values, not errors,
   and skip on failure. Only the top-level orchestrator returns an error. (§6.1)
3. **Detection is data-driven.** Add an entry to a spec table; don't add control flow. (§3.1)
4. **Cross-platform code splits by build tag**, not by sprinkling `runtime.GOOS` — *when* the code
   wouldn't compile on the other OS. Otherwise branch at runtime on `model.Platform*` constants. (§2)
5. **Every external command has an explicit timeout** via `RunWithTimeout`/`RunInDir`. Build commands
   from fixed argv; never interpolate untrusted input into a shell string. (§7)
6. **Raw secret values never get serialized.** Tag them `json:"-"`; emit a pre-redacted `Display`
   value plus a `SHA256` fingerprint, and redact in the detector. (§10)
7. **`model` is the single source of truth for every wire/output shape.** Explicit `snake_case`
   JSON tags; optional object → `*T,omitempty`; collection → bare slice (always `[]`). (§9)
8. **Logs go to stderr via `progress.Logger`; results go to stdout.** Pick the level by audience:
   `Warn` for "something expected was skipped", `Debug` for diagnostics. (§6.5)
9. **Concurrency is the exception.** Default to sequential code. When you must parallelize, bound it
   (`min(NumCPU, 8)`) with stdlib `sync` only. (§8)
10. **It must pass the gates:** `gofmt`, `go vet`, `go mod tidy` (no drift), `golangci-lint`,
    `go test -race`, `make smoke`, and `gosec` — on a `CGO_ENABLED=0` cross-compile to
    linux/darwin/windows. (§16)

---

## 1. Project shape & where code goes

- **Module:** `github.com/step-security/dev-machine-guard`, **Go 1.26** (pinned in `go.mod` and
  `.tool-versions`). Dependencies are deliberately minimal — stdlib first.
- **`CGO_ENABLED=0` everywhere.** The binary is pure-Go and cross-compiled. Do not introduce cgo or
  a dependency that requires it. Platform-native behavior comes from build tags + `golang.org/x/sys`,
  never cgo.
- **Two binaries** under `cmd/`:
  - `cmd/stepsecurity-dev-machine-guard` — the real agent/CLI. All product logic.
  - `cmd/stepsecurity-dev-machine-guard-task` — a Windows-only GUI-subsystem launcher
    (`-ldflags "-H windowsgui"`) whose only job is to give Task Scheduler a no-console parent.
    **Never add detection/CLI logic here.**
- **One responsibility per package.** Packages are small and noun-named after the thing they own.
  There is **no `utils`/`helpers` grab-bag** — resist creating one.
- **When to add a package vs a file.** Create a new `internal/` package only when the concern has its
  own OS-abstraction surface worth isolating at compile time (`winproc`, `tcc`, `lock`) or is a
  cohesive sub-domain with multiple files and its own doc (`detector/rules`, `detector/configaudit`).
  **Otherwise add a file to the existing package** — every detected tool is its own file in
  `internal/detector/` (`jetbrains.go`, `nodescan.go`, …), not its own package.
- **`doc.go`** is reserved for (a) a domain root with subpackages, or (b) a non-obvious engine whose
  trust/data-flow model deserves a long comment (`detector/rules/doc.go`). Ordinary leaf packages put
  the package comment atop the primary file.

The package map (own one responsibility each):

| Package | Owns |
|---|---|
| `model` | All shared data/wire types. **Dependency-free.** |
| `executor` | The `Executor` interface — every OS interaction (run cmd, file, env, user, GOOS). |
| `detector` | App/IDE/agent/package-manager/process detection. |
| `detector/rules` | Declarative, content-blind malicious-file scan engine. |
| `detector/configaudit` | Audits package-manager config files (npmrc, pip, yarn, pnpm, bun). |
| `cli` | Hand-rolled flag/verb parser → `cli.Config`. |
| `scan` | Community-mode orchestration → `model.ScanResult`. |
| `telemetry` | Enterprise payload assembly + upload. |
| `output` | JSON / HTML / pretty renderers. |
| `progress` | Leveled stderr logger + step spinners. |
| `config` / `featuregate` | Config loading; default-off feature flags. |
| `paths` | Single source of truth for on-disk locations. |
| `state` / `heartbeat` | Schema-versioned persistent JSON. |
| `schtasks` / `launchd` / `systemd` | Per-OS scheduler install/uninstall. |
| `lock` / `winproc` / `tcc` / `device` / `schedinfo` | Single-instance lock; Windows proc attrs; macOS TCC skip; machine identity; scheduler introspection. |
| `buildinfo` | Version const + ldflags-injected git metadata. |

---

## 2. Cross-platform code

### 2.1 The OS boundary is `executor.Executor`
Detectors, schedulers, and collectors take an `executor.Executor` and call `exec.Run(ctx, …)`,
`exec.FileExists`, `exec.LookPath`, `exec.IsRoot()`, `exec.GOOS()`, etc. — never `os/exec` or `os.*`
directly. This is what lets the entire codebase be unit-tested with `executor.Mock`. (Detail in §7.1.)

### 2.2 Split by build tag with a shared base file
When a function needs a different implementation per OS, put the **shared code** (orchestration and
the common entry point that *calls* the platform hook) in the unsuffixed `x.go`, and put each
platform implementation in an OS-suffixed file satisfying the same unexported signature.

```go
// fileattrs.go — compiles everywhere; owns the shared entry point
func fileAttrs(info os.FileInfo) model.FileAttrs {
    created, changed := statTimes(info) // ← platform hook
    return model.FileAttrs{
        SizeBytes: info.Size(), ModifiedAt: info.ModTime().Unix(),
        CreatedAt: created, ChangedAt: changed,
    }
}
```
```go
//go:build linux
package rules
func statTimes(info os.FileInfo) (created, changed int64) {
    st, _ := info.Sys().(*syscall.Stat_t)
    return 0, int64(st.Ctim.Sec) // Linux has no birth time
}
```
→ Canonical: `internal/detector/rules/fileattrs*.go`; `internal/detector/process*.go`;
`internal/detector/registry*.go`; `internal/lock/lock_{unix,windows}.go`.

### 2.3 Suffix shapes & the explicit `//go:build` line
- **Windows-vs-everything:** `_windows.go` + `_other.go` (tagged `//go:build !windows`).
- **macOS-vs-everything:** `_darwin.go` + `_other.go` (`!darwin`).
- **Each OS differs:** `_darwin.go` / `_linux.go` / `_windows.go` + `_other.go` catch-all.
- **`_other.go` is always the catch-all**, tagged with the explicit negation of every sibling
  (e.g. `//go:build !darwin && !linux && !windows`).
- **`_unix.go` vs `_other.go`** (both mean `!windows`): use `_unix` when the body genuinely uses
  POSIX syscalls (`syscall.Kill`, `Setpgid`); use `_other` for a generic/no-op fallback.
- **Always put an explicit `//go:build` line on line 1 of every split file**, even when the filename
  suffix already implies it — the catch-all *requires* it, and keeping it on all of them is the
  convention (symmetry + greppability).

### 2.4 No-op stub so callers stay unconditional
When a feature exists on only one OS, the other platform's file provides a no-op of the same
signature (documented as such) so call sites never need their own `if runtime.GOOS`.

```go
//go:build !windows
package winproc
// HideWindow is a no-op on non-Windows platforms.
func HideWindow(_ *exec.Cmd) {}
```
→ Canonical: `internal/winproc/winproc.go`, `internal/tcc/tcc_other.go`, `internal/config/config_other.go`.

### 2.5 Build tag vs runtime `GOOS` check
- Use a **build-tag split** when the code *wouldn't compile* on the other OS — it imports an OS-only
  package (`golang.org/x/sys/windows`) or uses an OS-only syscall type.
- Use a **runtime check** (`switch runtime.GOOS` / `exec.GOOS()`) when the code compiles everywhere
  and you're only branching behavior (which path, command name, install layout). Routing through
  `exec.GOOS()` (not `runtime.GOOS`) lets a mock simulate another OS via `SetGOOS(...)`.
- **Compare against `model.PlatformDarwin/Windows/Linux` constants, not string literals**, in
  production code.

### 2.6 Sanctioned exception
Omit the `_other`/catch-all variant **only** when the shared caller is itself platform-tagged so no
other OS can reach the symbol (e.g. `executor/statfs_{darwin,linux}.go`, reached only from
`executor_unix.go`). Add a one-line comment saying why no catch-all exists.

---

## 3. The detector pattern (the core idiom)

This is the most-imitated pattern in the repo. Get it right.

### 3.1 Data-driven: a spec table + a `Detect` loop
Every "what to look for" detector declares a package-level `var xxxDefinitions = []xxxSpec{…}` of
plain-data entries and ranges over it. **Adding a target = adding one struct literal**, never new
control flow.

```go
type cliToolSpec struct {
    Name, Vendor string
    Binaries     []string // PATH names, or ~-relative paths
    ConfigDirs   []string // ~-relative
    VersionFlag  string   // defaults to "--version"
    VerifyFunc   func(ctx context.Context, exec executor.Executor, binary string) bool // optional, rejects false positives
}

var cliToolDefinitions = []cliToolSpec{
    {Name: "claude-code", Vendor: "Anthropic",
        Binaries: []string{"claude", "~/.claude/local/claude"}, ConfigDirs: []string{"~/.claude"}},
    // ← add new tools here; nothing else changes
}
```
The spec is **pure data** with platform-keyed fields (`AppPath`/`WinPaths`/`LinuxPaths`,
`ConfigPath`/`WinConfigPath`). The `Detect` loop branches on `d.exec.GOOS()` to a per-OS helper.
→ Canonical: `internal/detector/{ide,aicli,mcp,agent,framework}.go`. The spec struct in the file is
the source of truth for its fields (the field list evolves — read the struct, don't trust prose).

### 3.2 Detector struct + constructor
A detector wraps the `executor.Executor` (plus any injected test seams). Constructor is `NewXxx(exec)`.

```go
type IDEDetector struct{ exec executor.Executor }
func NewIDEDetector(exec executor.Executor) *IDEDetector { return &IDEDetector{exec: exec} }
func (d *IDEDetector) Detect(ctx context.Context) []model.IDE { … }
```

### 3.3 `Detect` returns values, never errors, never panics
Inventory detectors return `[]model.X` and **silently skip** anything that fails (`continue` the
loop). No inventory `Detect` returns `error`. A finding is produced by populating a `model` struct and
appending only on positive detection. (Resilience rationale: §6.1.)
*(configaudit detectors are the documented variant — they return a single audit struct and embed soft
failures as `ParseError`/`Error` string fields; see §5.)*

### 3.4 Version extraction: static-first, exec-last, `"unknown"` floor
Resolve versions from on-disk metadata (`package.json`, `product-info.json`, `Info.plist`, registry)
**before** exec'ing any binary; the `--version` call is the last fallback, guarded by
`BinaryPath != "" && VersionFlag != ""`. This ordering is load-bearing — exec'ing a GUI binary can
flash a window or hang. Every failure path returns the literal string **`"unknown"`**, never `""`.
→ Canonical: `internal/detector/ide.go` (`resolveDarwinVersion`).

### 3.5 Path & discovery helpers (don't reinvent)
- `~/…` → `expandTilde(path, home)`; Windows `%VAR%` → `resolveEnvPath(exec, path)`; globs →
  `exec.Glob`. For version-in-folder-name dirs, **newest mtime wins**, never lexicographic sort
  (`"2024.9"` vs `"2024.10"`).
- **Layered fallback discovery:** cheap exact paths first, then a platform-native fallback (Windows
  registry Uninstall keys; Linux `LookPath` then `.desktop` `Exec=`).
- Prefer **native APIs over subprocesses** for process checks (`/proc/<pid>/comm` on Linux, Toolhelp32
  on Windows; `pgrep` only on macOS).

### 3.6 Bounded directory walks
Project/config discovery uses `filepath.WalkDir` with: the TCC skipper first (nil-safe), then skip
`node_modules`/`.git`/`.cache`/dotdirs via `SkipDir`, then a hard `max…` count cap via `SkipAll`.
Caps prevent monorepo payload blow-ups. (Walk error-handling shape: §6.3.)
→ Canonical: `internal/detector/nodeproject.go` (`maxNodeProjects = 1000`).

### 3.7 Adding a detection — checklist
1. Add one entry to the right spec table in `internal/detector/`.
2. If it needs false-positive rejection, set `VerifyFunc` (where the spec supports it).
3. Add a `_test.go` case using `executor.NewMock()` (§15.3).
4. Update `SCAN_COVERAGE.md` (and `README.md` if user-facing).
5. Run `make lint && make test && make smoke`.

---

## 4. The rules engine (declarative, content-blind detection)

A second, separate detection model lives in `internal/detector/rules/`. Read `rules/doc.go` first.

- **Backend-authored declarative rules** (`RuleSet → Rule → ConditionGroup → Condition`) matched
  against the filesystem. A condition can only ask: does this path exist; does content match this
  RE2; does the file's SHA-256 equal this hex? It yields **only a boolean** — **no matched text is
  ever captured**, and no rule field may carry a command/script/URL.
- **No embedded rule pack.** Any fetch/parse/validate failure ⇒ scan nothing this run, **never fail
  the run**. Lifecycle is `Fetch → Prepare → Scan`; `Prepare()` is the sole validation gate
  (unique IDs, valid RE2, 64-hex sha256, clamps caps) and rejects the **entire** bundle on any error.
  `…OrEmpty` wrappers turn every failure into a no-op empty `RuleSet` + a log.
- **Hard-bounded:** per-file size, global file count, per-rule match cap, total time budget — all
  clamped in `NewEngine`. Symlinks are never followed.
- **Invoked only from enterprise telemetry**, behind `config.IsEnterpriseMode()`. The
  `malicious_file_scan` phase is recorded **only when rules were actually available** (its presence is
  the backend's "device was scanned" signal).

If you author new conditions/caps, preserve all three invariants: **content-blind, fail-safe, bounded.**

---

## 5. The configaudit sub-pattern

Each package-manager config auditor (`npmrc`, `pipconfig`, `yarn`, `pnpm`, `bunfig`) splits into
three concerns:

1. **`xxx.go`** — detector struct, `Detect`, discovery walk, per-file metadata (`collectFile`).
2. **`xxx_parse.go`** — a **pure, tolerant** `parseXxx([]byte) → []entry`: skip malformed lines, never
   abort, and **never expand `${VAR}`** (the literal form is what distinguishes a hardcoded secret
   from an env reference).
3. **`xxx_findings.go`** (pip today) — a finding catalog with **stable IDs** (`pip-001…`) and a
   `Severity` enum (`CRITICAL|HIGH|MEDIUM|LOW|INFO`).

Conventions within `Detect`:
- Build the file list with a `seen map[string]bool` + an `add(scope, path)` closure that absolutizes
  and dedups.
- **`collectFile` always returns a record** — a non-existent file surfaces with `Exists=false`
  ("we looked here, found nothing"). `Lstat` first so symlinks aren't silently followed; record
  owner/mode/mtime/SHA-256, then parse.
- Secrets are SHA-256'd (rotation tracking) and only ever shown redacted (§10).

---

## 6. Error handling, resilience & logging

### 6.1 The resilience spine
`scan.Run` / `telemetry.Run` call each detector explicitly and in sequence, wrapped in
`log.StepStart(…)` / `log.StepDone(time.Since(start))`. Because inventory detectors can't return an
error (§3.3), one failing detector can't abort the run. **Only the orchestrator returns an `error`**,
and only the top-level `main` exits on it:
```go
if err := scan.Run(exec, log, cfg); err != nil {
    log.Error("%v", err)
    os.Exit(1)
}
```
There is **no detector registry** and **no `recover` around detectors** — resilience comes from the
return-value contract, not panic recovery.

### 6.2 Per-item failure: log + return zero
Inside a detector, a failed command or unparseable output is logged and skipped — never propagated.
Severity convention: **`Warn`** when something the user expected to scan failed ("results may be
incomplete"); **`Debug`** when a tool simply isn't present (expected absence).
```go
stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 15*time.Second, pipPath, "list", "--format", "json")
if msg := pmRunError("pip list", exitCode, err); msg != "" {
    d.log.Warn("python venv scan failed: %s — results may be incomplete", msg)
    return nil // skip, never propagate
}
```

### 6.3 Filesystem walks discard the walk error
```go
_ = filepath.WalkDir(dir, func(path string, e os.DirEntry, err error) error {
    if err != nil { return nil }                         // unreadable entry — skip, keep walking
    if e.IsDir() && d.skipper.ShouldSkip(path, dir) { return filepath.SkipDir }
    if len(projects) >= maxNodeProjects { return filepath.SkipAll }
    …
    return nil
})
```

### 6.4 Error construction
- **Wrap with `%w` and a lowercase gerund prefix:** `fmt.Errorf("acquiring lock: %w", err)`. In
  packages that self-prefix (`state:`, `rules:`, `ingest:`, `telemetry-out:`), keep the prefix.
- **Sentinels are unexported** (`var errWalkStop = errors.New("rules: walk stopped")`) for in-package
  `errors.Is` branching. There are **no exported `ErrX`**. Use inline `errors.New` for guard clauses.
- **Match with `errors.Is`** (`os.ErrExist`, `fs.ErrNotExist`, `context.DeadlineExceeded`, local
  sentinels); use `errors.As` only to extract a typed value (e.g. `*exec.ExitError`).

### 6.5 Logging = `progress.Logger`, stderr only
There is **one** logging abstraction: `*progress.Logger`, leveled
(`Off < Error < Warn < Info < Debug`, default Info). Every emitter writes to **`os.Stderr`**; stdout
carries **only** results (JSON/HTML/pretty). The user-vs-diagnostic distinction is the **level**, not
the stream:
- `Progress` / `StepStart` / `StepDone` → user-facing status (Info)
- `Warn` → user-facing "skipped / incomplete" (Warn)
- `Error` → user-facing fatal (Error)
- `Debug` → operator diagnostics: counts, durations, exit codes, "tool not found" (Debug)

Thread a `*progress.Logger` into your type; default it to `progress.NewNoop()` until one is injected.
Never `fmt.Fprintf(os.Stderr, …)` from normal code (the only legitimate homes are the logger itself
and pre-logger startup/signal paths).

### 6.6 `context.Context` & timeouts
`ctx` is the first parameter through every detector and command. `context.Background()` is legitimate
only at entry points (and deliberately in cleanup/`recover` paths where the inherited ctx may *be* the
failure). Long operations carve named per-phase budgets off the parent.

### 6.7 `panic`/`recover` — only at fail-open boundaries
Exactly two sanctioned `recover()` sites, both documented: the hook entry point (silent fail-open so a
panic still exits 0) and the top-level `telemetry.Run` (converts a panic into a reported failure row
before exit). **Do not add `recover()` inside detectors or per-item loops.**

### 6.8 Treat external data as hostile
Bound reads (`io.LimitReader`), `TrimSpace` + empty-check before `json.Unmarshal`, tolerate unmarshal
errors by logging + returning zero, and validate semantic sanity (non-empty key fields) even when the
exit code is 0.

---

## 7. External command execution

### 7.1 Everything through `executor.Executor`
`os/exec` appears **only** inside `internal/executor/` (and a couple of clearly-commented device
probes). Detectors call `exec.RunWithTimeout(…)`, never `exec.Command`. The interface centralizes
window-hiding, process-group kill, and timeouts — and makes everything mockable.

### 7.2 Fixed argv, no shell
Commands are `exec.CommandContext(ctx, name, args...)` with a static binary name and literal
`[]string` flags. Untrusted/variable values (project dirs, package names) are passed as **separate
argv elements** so the OS never word-splits or glob-expands them. There is no exec allowlist —
safety rests on fixed-argv construction + quoting.

### 7.3 Explicit per-call timeout
Use `RunWithTimeout` / `RunInDir`, never bare `Run`, for third-party tools. A deadline maps to exit
code **124** (`timeout` convention). De-facto taxonomy:

| Timeout | Use |
|---|---|
| `10s` | version / metadata probes |
| `15–30s` | config reads, package-list dumps |
| `60s` | global package-manager scans |

### 7.4 Kill the process group (Unix) & suppress the console (Windows)
- Every `Real.Run` calls `setupKillgroupOnCancel(cmd)` (Unix: `Setpgid` + `cmd.Cancel` does
  `kill(-pid, SIGKILL)`, plus `WaitDelay`) so forked grandchildren can't hold pipes open past the
  deadline. *(This is a no-op on Windows today — timeout guarantees are weaker there.)*
- Every `*exec.Cmd` you construct calls `winproc.HideWindow(cmd)` (no-op off Windows) so scheduled
  `powershell`/`cmd` children don't flash a console.

### 7.5 `shlex` parses, never builds
`github.com/google/shlex` is used **only** to parse observed command strings (from hook/telemetry
events), never to assemble an argv we then execute. Idiom: `shlex.Split`, fall back to
`strings.Fields` on error.

### 7.6 When a shell is unavoidable, quote every token
The two legitimate shell paths (`RunAsUser` sourcing the user's rc; the Node PM-version PATH-prepend
fallback) run the binary, **every arg, and every path** through `platformShellQuote` /
`posixShellQuote` (POSIX `'…'` with `'\''`; Windows `"…"` with `\"`).

---

## 8. Concurrency

- **Default sequential.** The whole scan is a straight line of `Detect(ctx, …)` calls — no goroutines.
- **Stdlib only.** No `errgroup` / `x/sync` / `semaphore` in `go.mod`. Use `sync` + channels.
- **Parallelize only a proven hot loop, and bound it.** The single data-parallel path is per-project
  Node scanning, capped at `min(NumCPU, 8)`.
- **The canonical worker pool:** buffered jobs channel + `WaitGroup`; each worker writes only its own
  pre-sized result slot (disjoint ownership ⇒ **no mutex**); producer feeds indices then `close()`s;
  `wg.Wait()` joins.
```go
slots := make([]slot, len(projects)) // each idx owned by exactly one worker
jobs := make(chan int, len(missIdx))
var wg sync.WaitGroup
for range scanWorkerCount(s.exec) { // min(NumCPU, 8)
    wg.Add(1)
    go func() {
        defer wg.Done()
        for idx := range jobs {
            if r, ok := s.scanProject(ctx, projects[idx].dir, slots[idx].pm); ok {
                slots[idx].result, slots[idx].populated = r, true // disjoint write
            }
        }
    }()
}
for _, i := range missIdx { jobs <- i }
close(jobs); wg.Wait()
```
- **Background goroutines** must be self-bounding with a defined drain/exit on `ctx.Done()`, share a
  `context`, and serialize a shared sink with a `sync.Mutex` (e.g. the telemetry progress sender:
  buffered-1 "latest wins" channel + mutex + drain-then-exit).
- **Memoize process-invariant probes with `sync.Once`** — and run the probe on `context.Background()`
  with its own timeout (a `Once` consumes its slot on first call; a caller's canceled ctx must not
  poison the cache).

---

## 9. Data model, JSON & the wire contract

### 9.1 `model` is the single source of truth, dependency-free
All wire/output shapes are plain structs in `internal/model/`. The package imports nothing. Never
redefine a shape elsewhere — `telemetry`, `output`, and `scan` all embed `model.*` types so the three
layers can't drift.

### 9.2 JSON tag conventions
- **Explicit `snake_case` tag on every serialized field.** Go field stays `PascalCase`; the tag
  bridges. Never rely on default casing.
- **Optional object → pointer + `omitempty`** (drops the key when nil).
- **Collection → bare slice, no `omitempty`** (always renders `[]`, stable shape). Normalize nil
  slices to `[]model.T{}` before marshalling.
- **Optional scalar metadata → `omitempty`.**
- **Tri-state → `*bool` + `omitempty`** (distinguishes "unknown" from "false"); nil-check before deref.
```go
BrewPkgManager *PkgManager   `json:"brew_package_manager,omitempty"` // optional object
BrewFormulae   []BrewPackage `json:"brew_formulae"`                  // collection → always []
NPMRCAudit     *NPMRCAudit   `json:"npmrc_audit,omitempty"`          // optional sub-report (gate off → nil → dropped)
IsRunning      *bool         `json:"is_running,omitempty"`           // tri-state
```
The JSON shape is **under test** — `model/scanresult_jsonshape_test.go` asserts optional sub-reports
are *absent* from an empty `ScanResult`. A new `*Audit`-style field must be `omitempty` or the test
fails.

### 9.3 Field types
- **Times:** `int64` unix seconds, named `*_unix` / `*_time_unix` / `*_at`; add an ISO twin
  (`scan_timestamp_iso string`) only when a human-readable mirror is needed. `0` = unavailable.
- **Sizes:** `*_bytes` (`uint64` for capacities). **Durations:** `*_ms` (`int64`).
- **Raw command output:** base64 into `*_base64` string fields, never nested JSON.
- **Enums:** untyped `string` fields, allowed set documented inline; shared values get grouped
  `const (...)` (e.g. `model.Platform*`), and `output` owns the `…DisplayName`/`…Label` switch.

### 9.4 Telemetry payload & schema version
The enterprise wire shape is `telemetry.Payload` (a superset of `model.ScanResult`), assembled as one
struct literal. New telemetry fields are added there and wired from the `model` struct they reference.
Bump `CurrentPayloadSchemaVersion` when the backend cares; gate additive sibling fields with
`omitempty`.

### 9.5 "New serialized field" checklist
snake_case tag → choose pointer/slice/omitempty per §9.2 → if credential-bearing add `json:"-"` raw +
`Display` + `SHA256` (§10) → wire into `telemetry.Payload` **and** the relevant `output` view-models →
bump the schema version if the backend depends on it.

---

## 10. Secrets & privacy (first-class)

- **Raw secret values never serialize.** Hold the raw value in a `json:"-"` field used only internally;
  emit a pre-redacted `Display`/`DisplayValue` and a `ValueSHA256` fingerprint.
- **Redact in the detector**, so the value is safe before it ever reaches `model`/`telemetry`/`output`.
  Redaction is `***` (short) or `***last4`. **Hash the raw value** (before redaction) so credential
  rotation is detectable without storing plaintext.
```go
type NPMRCEntry struct {
    Key          string `json:"key"`
    DisplayValue string `json:"display_value"`            // pre-redacted: ***last4
    ValueSHA256  string `json:"value_sha256,omitempty"`   // fingerprint of the RAW value
}
// PipKeyValue.Values []string `json:"-"` // raw; can hold user:pass@host — NEVER serialized
```
- **The rule-scan engine is content-free by design** — it ships paths, hashes, and per-condition
  booleans, never file content.
- **Execution-log capture is unredacted.** Enterprise mode tees stderr into a 1 MB ring buffer and
  ships it base64'd — so **never write a secret to stderr** (no redaction layer exists there).
- The PR template requires confirming "no secrets or credentials included."

---

## 11. Telemetry & HTTP

- **Stdlib `net/http`, no framework.** `http.NewRequestWithContext` + `&http.Client{Timeout: …}`.
  Every backend call sets three headers and uses the endpoint template:
```go
req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
req.Header.Set("Content-Type", "application/json")
req.Header.Set("Authorization", "Bearer "+config.APIKey)
req.Header.Set("X-Agent-Version", buildinfo.Version)
// endpoint := fmt.Sprintf("%s/v1/%s/developer-mdm-agent/telemetry/<route>", config.APIEndpoint, config.CustomerID)
```
- **Best-effort: telemetry never blocks the scan.** Failures are logged, retried a bounded number of
  times with fixed backoff (`select` on `time.After` vs `ctx.Done()`), then abandoned. Run-status
  helpers "never return an error — running the scan is the priority."
- **Bulk payload path:** `json.Marshal` → gzip → request a presigned S3 URL (`is_compressed: true`) →
  `PUT` gzipped bytes with `Content-Type: application/json` (must match the signed header) → notify
  backend. Verify the PUT reached AWS by checking for `x-amz-request-id`/`x-amz-id-2` response headers
  before trusting a 200 (TLS-proxy detection).
- **Community vs enterprise** is gated by `config.IsEnterpriseMode()`. Community emits
  `model.ScanResult`; enterprise emits `telemetry.Payload`.

---

## 12. Output & rendering

- **Single dispatch site**, free functions (no `Renderer` interface):
```go
switch cfg.OutputFormat {
case "json": return output.JSON(os.Stdout, result)
case "html": return output.HTML(cfg.HTMLOutputFile, result)
default:     return output.Pretty(os.Stdout, result, cfg.ColorMode)
}
```
  Renderers share a convention: `func(w io.Writer, result *model.ScanResult, colorMode string) error`
  (verbose per-tool views take `(w, audit, dev, colorMode)`).
- **JSON:** `json.NewEncoder(w)` with two-space indent and **`SetEscapeHTML(false)`** (so URLs/paths
  aren't mangled).
- **HTML:** one self-contained `const htmlTemplate` (inline CSS/JS, no external assets) rendered with
  **`html/template`** (auto-escaping); presentation logic via a `template.FuncMap`.
- **Pretty/console:** `fmt.Fprintf(w, …)` with a `*colors` struct of ANSI codes; `setupColors(mode)`
  honors `always`/`never`, and `auto` enables color only on a TTY. When disabled, the struct is
  empty strings so the same format strings emit plain text.
- **`--json` forces the logger to `LevelError`** to keep stdout clean for pipes (errors still go to
  stderr).

---

## 13. CLI & entrypoints

- **Two binaries** (§1). Don't add logic to the `-task` launcher.
- **`main()` dispatches; packages implement.** `main` parses, resolves config/logging, then
  `switch cfg.Command` and immediately calls into a package. Work functions take the uniform
  signature **`Run(exec executor.Executor, log *progress.Logger, cfg *cli.Config)`** and read `cfg.*`
  directly — don't thread individual flag values as separate params.
- **Hand-rolled parser in `internal/cli` — no `flag`, no `cobra`.** Parsing is a manual
  `for i < len(args) { switch … }` loop. Verbs set `cfg.Command` to a canonical string; two-word verbs
  (`configure show`, `hooks install`) peek at `args[i+1]`.
- **Add-a-flag recipe:** (1) add a field to `cli.Config` with a doc comment naming the flag; (2) add
  the parse `case` (support both `--x val` and `--x=val` for value flags); (3) read `cfg.X` in the work
  package; (4) add a `--help` line + a `TestParse_*` test. Dev-only flags also get an env fallback and
  are omitted from `--help`. Optional on/off flags are `*bool` (nil = auto).
```go
case arg == "--api-key":
    i++
    if i >= len(args) { return nil, fmt.Errorf("--api-key requires a value") }
    cfg.ConfigAPIKey = args[i]
case strings.HasPrefix(arg, "--api-key="):
    cfg.ConfigAPIKey = strings.TrimPrefix(arg, "--api-key=")
```
- **Exit-code contract** (scheduler-facing — use these, don't invent new ones): `0` success ·
  `1` generic failure/usage/config error · `2` execution-watchdog hard timeout (and `--exec` launcher
  misuse) · `130` SIGINT/SIGTERM. **The hidden `_hook` path MUST exit `0` even on bad args** (agents
  treat any non-zero as a hook block).
- **Version:** the semantic version is the `Version` const in `internal/buildinfo/version.go` — **bump
  it there** (the Makefile greps it for MSI versioning). Git commit/tag/branch are `-ldflags`-injected
  vars. Print via `buildinfo.VersionString()`.
- **Signals live in `telemetry.Run`**, not the entrypoint. `main` arms a self-signaling watchdog goroutine
  (`armExecutionWatchdog`) before telemetry runs. Don't add `signal.Notify` to `main`.
- Cross-flag constraints (mutual exclusion) are validated **after** the parse loop and return a
  descriptive `error` (never `os.Exit` from the validation).

---

## 14. OS integration & lifecycle

- **Scheduler packages share one shape.** `schtasks` / `launchd` / `systemd` each export
  `Install(exec, log) error` and `Uninstall(exec, log) error`, selected by a **single**
  `switch runtime.GOOS` in `main`. Never branch on OS in any other caller.
- **Install is idempotent** (it's the upgrade path): probe `isConfigured`, and if present log
  "Upgrading…", call the internal uninstall, then recreate. **Uninstall tolerates "not found"** and
  best-effort teardown ignores non-zero exits.
```go
if isConfigured(ctx, exec) {
    log.Progress("Existing agent installation detected. Upgrading...")
    if err := doUninstall(ctx, exec, log); err != nil {
        log.Warn("failed to remove previous install: %v — continuing anyway", err)
    }
}
```
- **plist/unit generation uses `text/template`** + a typed data struct + a package-level `const`
  template, with **every value escaped** through a per-format helper (`text/template` does no
  escaping). *(Windows schtasks XML is the documented exception — it's spliced via string-index
  patching of the `/query /xml` → `/create /xml` round-trip.)*
- **Scan frequency has one source:** `config.ScanFrequencyHours` (default `4` when `<= 0`), translated
  per-scheduler (HOURLY/DAILY `/mo`, plist `StartInterval`, `OnUnitActiveSec`).
- **Privilege is one call: `exec.IsRoot()`** (Unix `getuid()==0`; Windows elevated-token). Never
  re-derive elevation. Install layout forks on it (system-wide vs per-user).
- **Never hardcode a path — ask `internal/paths`.** Resolution precedence: `--install-dir` >
  `config.InstallDir` > `$STEPSECURITY_HOME` > `~/.stepsecurity`. A `""` return means output is
  **disabled** — callers MUST skip writing.
- **Config: build-time values win.** Enterprise config globals start as `"{{PLACEHOLDER}}"` strings the
  installer substitutes; `config.Load()` applies a `config.json` field **only if the in-memory value is
  still a placeholder/empty**. `Load` tolerates a missing/garbage file (returns, leaving defaults).
- **Persistent JSON state is schema-versioned, atomically written, tolerantly read:**
```go
// the canonical atomic-write recipe (state.go; mirrored by heartbeat)
tmp, _ := os.CreateTemp(dir, ".scan-state-*.tmp")
_, _ = tmp.Write(data); _ = tmp.Sync(); _ = tmp.Close()
_ = os.Remove(dest)               // Windows Rename won't overwrite; no-op on POSIX
_ = os.Rename(tmp.Name(), dest)
```
  Reads return a fresh empty value on missing file / parse error / `SchemaVersion` mismatch, and
  normalize nil maps so callers never nil-check. A corrupt state file must never break a run.
- **Single-instance lock** = atomic PID lockfile (`O_CREATE|O_EXCL`, `0o600`) with a liveness check
  to reclaim stale locks (Unix `Kill(pid, 0)`; Windows `OpenProcess`).
- **Feature gates** are typed `Feature` string consts in a **default-off allowlist map**; check
  `featuregate.IsEnabled(featuregate.FeatureX)`. The only override is global
  (`STEPSECURITY_OVERRIDE_GATE` / `--override-gate`). Gates are **not** sourced from `config.json`.
- **Device/scheduler introspection is best-effort**, ordered fallback chains with short timeouts that
  floor to `"unknown"` and record failures as warnings — never fatal.

---

## 15. Testing

### 15.1 Stdlib `testing` only
No testify/go-cmp. Assert with `t.Errorf` / `t.Fatalf` in `got, want` phrasing (`Fatalf` for
setup/unrecoverable; `Errorf` for value mismatches so table rows continue).

### 15.2 Table-driven by default
Anonymous `struct` slice named `tests` (or `cases`), `name` field first, loop var `tc`, one
`t.Run(tc.name, …)` per row. Top-level functions are `TestType_Scenario`.
```go
tests := []struct{ name, path string; want bool }{
    {"documents skipped", "/Users/alice/Documents", true},
    {"code dir not skipped", "/Users/alice/code", false},
}
for _, tc := range tests {
    t.Run(tc.name, func(t *testing.T) {
        if got := s.ShouldSkip(tc.path, root); got != tc.want {
            t.Errorf("ShouldSkip(%q) = %v, want %v", tc.path, got, tc.want)
        }
    })
}
```

### 15.3 The canonical detector test: `executor.Mock` + `t.TempDir`
`executor.Mock` is **production code** (`internal/executor/mock.go`) with ~21 setters
(`SetCommand`, `SetFile`, `SetDir`, `SetPath`, `SetGOOS`, `SetIsRoot`, `SetHomeDir`, …). Inject it to
stub the OS; commands are keyed by the exact joined `"name arg1 arg2"` string.
```go
mock := executor.NewMock()
mock.SetGOOS("windows")
mock.SetCommand("", "", 0, "schtasks", "/query", "/tn", taskName)
if got := isConfigured(context.Background(), mock); !got {
    t.Error("expected isConfigured to return true when task exists")
}
```
For real file I/O, build a tree under `t.TempDir()` and point home at it via `mock.SetHomeDir(tmp)` or
`t.Setenv("HOME", tmp)`. Below the executor line (raw `os.Stat` ownership, git), detectors expose
**function-typed struct fields** (`ownerLookup`, `gitTracked`, `inGitRepo`) wired to real impls in the
constructor and overwritten with stubs in tests. Inject time via a `now func() time.Time` seam +
`fakeClock`; **never `time.Sleep`.** Custom fakes are small hand-written `fakeX`/`stubX` structs.

### 15.4 Platform tests
Either a whole-file build-tag split mirroring the production file
(`tcc_darwin_test.go` ↔ `tcc_other_test.go`), or a `runtime.GOOS` guard + `t.Skip` for individual
rows. Use `mock.SetGOOS("windows")` to unit-test another OS's *logic* from any host (no skip needed).

### 15.5 Helpers, parallelism, scope
Helpers are unexported, file-local, take `*testing.T`, and call `t.Helper()` first (`must`-prefixed
when they fatal). **Do not use `t.Parallel()`** — the suite is serial by design (`t.Setenv` is
process-global; `t.TempDir` is used heavily). Tests are **white-box** (same package) so they can reach
unexported funcs/fields; external `_test` packages are the rare exception. `make test` runs
`go test ./... -race -count=1`; `make smoke` runs `tests/test_smoke_go.sh` against the built binary.
Every new detector should ship a `_test.go` against `executor.NewMock()`.

---

## 16. Tooling, CI gates & repo conventions

**The PR cannot merge unless these pass** (see `.github/workflows/tests.yml`, `gosec.yml`):
- `gofmt -l .` is empty (run `go fmt ./...`)
- `go vet ./...`
- `go mod tidy` produces **no diff** in `go.mod`/`go.sum`
- `golangci-lint run ./...` (built from source against Go 1.26; config in `.golangci.yml`)
- `go test ./... -race -count=1`
- `make smoke`
- `gosec` (SARIF to the Security tab; `-no-fail` but findings are reviewed)
- `go build ./...` cross-compiles clean for **linux/amd64, darwin/arm64, windows/amd64** with
  `CGO_ENABLED=0`

Run `make lint && make test && make smoke` locally before pushing.

**GitHub Actions doctrine** (this is a supply-chain-security product — match it):
- **Pin every action to a full commit SHA** (`uses: actions/checkout@<sha> # v4.3.1`), never a
  floating tag.
- Every workflow job runs `step-security/harden-runner` with `egress-policy: audit`.

**Comments & docs:**
- Comments are **terse and explain *why***, not *what* — especially the non-obvious: edge cases,
  platform quirks, and incident references (e.g. "exec'ing a GUI binary can flash a window/hang"). The
  `model` structs are densely commented because they're a wire contract; match that density only where
  the *why* is non-obvious.
- Match the surrounding file's style. Don't add narration to routine code.

**Versioning & changelog:**
- **SemVer:** major = breaking CLI/output/schema change; minor = new detection/feature/format;
  patch = fix/docs. Bump `internal/buildinfo/version.go`.
- Keep `CHANGELOG.md` in [Keep a Changelog](https://keepachangelog.com) form (`Added`/`Changed`/`Fixed`).
- Adding a detection? Update `SCAN_COVERAGE.md` and `README.md`.

---

## 17. Additive improvement backlog (FUTURE — not part of these guidelines)

These surfaced during analysis. They are **observations for future consideration**, each purely
additive (no behavior change). **Adopting this doc does NOT mean doing any of these** — they need their
own issues/PRs and review. Listed so the knowledge isn't lost.

- **Refresh stale contributor docs.** `docs/adding-detections.md` and `CONTRIBUTING.md` have drifted
  from the code: they reference `ai_cli.go` (now `aicli.go`) and an agent field `DetectionPaths` (now
  `ConfigDirs`), show an IDE example pointing `BinaryPath` at a *GUI* binary (the documented
  hang/flash anti-pattern — should be a CLI shim), and omit `LinuxPaths`/`LinuxBinary`/`AppPathAlts`/
  `RegistryName`/`VerifyFunc`. **Highest-leverage** fix since it's what new contributors read.
- **Author a rules-engine doc** (`docs/detection-rules.md`) describing the `RuleSet/Rule/
  ConditionGroup/Condition` JSON shape and glob semantics, so rule authors don't read Go.
- **Codify shared idioms as helpers:** an `internal/exitcode` package for the §13 exit-code contract;
  `paths.LockFile()` + exported state/heartbeat filename consts (today the lockfile bypasses `paths`);
  an exported `output.NewEncoder(w)` for the canonical indent + `SetEscapeHTML(false)` (duplicated in
  `main`); a shared `isContextTimeout(err)` and a promoted `cmdError(...)` normalizer.
- **Lock more contracts under test:** a `model/doc.go` "new field" checklist; a reflection test
  asserting credential-bearing structs tag raw fields `json:"-"`; a golden JSON-shape test for
  `telemetry.Payload` (only `ScanResult` is locked today).
- **Close platform asymmetries:** a Windows JobObject group-kill so `setupKillgroupOnCancel` has teeth
  on Windows; a `config` schema-version field for forward-compatible migrations.
- **Mechanical guards (CI):** assert `os/exec` appears only under `internal/executor/`; assert each new
  detector ships a `_test.go`.
- **Minor perf:** memoize `device.Gather` with `sync.Once` (it reshells `ioreg`/`dmidecode` per call).

---

*Maintenance: when a convention here stops matching the code, update this doc in the same PR that
changes the pattern — a guideline that lies is worse than none.*
