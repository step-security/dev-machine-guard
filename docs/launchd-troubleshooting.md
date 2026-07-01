# launchd Troubleshooting (macOS)

Command reference for the Dev Machine Guard launchd job (label
`com.stepsecurity.agent`).

**How periodic runs work:** the MDM loader installs a launchd plist with a
`StartInterval` (default 4h). Each tick launchd re-runs the **loader script**,
which auto-updates the binary, then runs `send-telemetry`. `RunAtLoad` is
`false`, so loading the plist (login / boot / install) never triggers a scan —
only the interval does. The one-off initial scan runs explicitly at install
time. To force an out-of-cycle run, `kickstart` it (or run the loader by hand).

## Scheduling: `RunAtLoad` and `StartInterval`

`RunAtLoad` controls one thing — whether launchd runs the job **once,
immediately, the moment the plist loads**:

- `<true/>` — runs as soon as the job loads. "Load" means boot (LaunchDaemon) /
  login (LaunchAgent), **and** every manual `launchctl bootstrap` / `load`. So a
  LaunchAgent would re-run on every login and every reload.
- `<false/>` (our setting, and the default) — does **not** run at load. The job
  sits idle until another trigger fires it: here that's `StartInterval`, or a
  manual `launchctl kickstart`.

```xml
<key>StartInterval</key>
<integer>14400</integer>   <!-- fire every 4h -->
<key>RunAtLoad</key>
<false/>                    <!-- but NOT at load -->
```

The cadence therefore comes entirely from `StartInterval`. `RunAtLoad=false`
avoids a redundant scan on every login/reboot (and a fleet-wide boot-time
stampede); the installer instead runs one explicit `send-telemetry` at install,
then lets the interval pace the rest.

**Consequence:** after a `bootstrap` / `load` / reload, **nothing runs on its
own** — use `kickstart` (see Force a run) to trigger a scan immediately.
(`RunAtLoad` is a one-shot-at-load trigger, unrelated to `KeepAlive`, which
continuously restarts a long-running daemon — a short-lived scan uses neither.)

## Variants

Almost always a per-user **LaunchAgent** running as the console user — that's
what the loader installs. The loader (and every version-specific loader script)
**never** creates a root daemon: even when MDM runs it as root it resolves the
console user and installs a per-user LaunchAgent, and aborts (`no_user`) if no
one is logged in rather than falling back to root. A root **LaunchDaemon** under
`/Library/LaunchDaemons/` only appears from a **legacy (≤1.8.x) agent script**
installed as root (pre-loader), or a manual `sudo <binary> install` (the Go
binary's installer has a root path the loader never invokes). Check for one — to
clean up a leftover — but current tooling won't create it.

|         | Per-user **LaunchAgent** (expected)                   | Root **LaunchDaemon** (rare)                          |
| ------- | ----------------------------------------------------- | ----------------------------------------------------- |
| Plist   | `~/Library/LaunchAgents/com.stepsecurity.agent.plist` | `/Library/LaunchDaemons/com.stepsecurity.agent.plist` |
| Domain  | `gui/$(id -u)`                                        | `system`                                              |
| Runs as | console user                                          | root                                                  |
| Logs    | `~/.stepsecurity/agent.log`, `agent.error.log`        | `/var/log/stepsecurity/agent.log`, `agent.error.log`  |
| `sudo`  | no                                                    | yes (use the `system` domain)                         |

Loader-managed (MDM, auto-updates) vs binary-managed (manual `install`) — tell
them apart by what the plist runs:

```bash
plutil -p "$PLIST" | grep -A4 ProgramArguments
# /bin/bash …/stepsecurity-loader.sh send-telemetry   -> loader-managed (auto-updates each tick)
# …/stepsecurity-dev-machine-guard send-telemetry      -> binary-managed (no auto-update)
```

## Setup

```bash
LABEL=com.stepsecurity.agent

# Expected: per-user LaunchAgent
DOMAIN="gui/$(id -u)"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGDIR="$HOME/.stepsecurity"

# Check whether a root LaunchDaemon is also present (rare). If it is, redo with
# sudo and: DOMAIN=system  PLIST=/Library/LaunchDaemons/$LABEL.plist  LOGDIR=/var/log/stepsecurity
ls -la "$HOME/Library/LaunchAgents/$LABEL.plist" 2>&1
ls -la "/Library/LaunchDaemons/$LABEL.plist" 2>&1
```

## Status

```bash
launchctl list | grep stepsec                          # loaded? PID + last exit
launchctl list "$LABEL"                                 # one-job summary
launchctl print "$DOMAIN/$LABEL"                        # full state, schedule, last exit
launchctl print-disabled "$DOMAIN" | grep stepsec       # disabled override? (loads but never runs)
launchctl enable "$DOMAIN/$LABEL"                        # clear a disable override
```

## Inspect plist

```bash
plutil -p "$PLIST"                                      # readable dump
plutil -lint "$PLIST"                                   # validate XML
plutil -p "$PLIST" | grep -A4 ProgramArguments          # loader script vs binary (see Variants)
/usr/libexec/PlistBuddy -c "Print :StartInterval" "$PLIST"          # seconds (14400 = 4h)
/usr/libexec/PlistBuddy -c "Print :EnvironmentVariables" "$PLIST"   # baked HOME / STEPSECURITY_HOME
```

## Config & version

```bash
cat "$HOME/.stepsecurity/config.json"                   # effective config (contains api_key)
cat "$HOME/.stepsecurity/.current_version"              # version the loader last installed
"$HOME/.stepsecurity/bin/stepsecurity-dev-machine-guard" --version   # running binary version
ls -la "$HOME/.stepsecurity" "$HOME/.stepsecurity/bin"  # owner should be the console user, not root
```

## Logs

```bash
tail -n 100 "$LOGDIR/agent.log"                         # scheduled-run stdout
tail -n 100 "$LOGDIR/agent.error.log"                   # scheduled-run stderr (rotates to .prev at 5 MiB)
tail -f "$LOGDIR"/agent.log "$LOGDIR"/agent.error.log   # watch live
tail -n 50 "$HOME/.stepsecurity/ai-agent-hook-errors.jsonl"   # AI-agent hook errors
stat -f '%Sm' "$LOGDIR/agent.log"                       # last scheduled-run time
log show --predicate 'process == "launchd"' --last 2h | grep -i stepsec   # launchd's own view
```

## Force a run

```bash
launchctl kickstart -k "$DOMAIN/$LABEL"                 # run now (-k restarts if in-flight)
/bin/bash "$HOME/.stepsecurity/bin/stepsecurity-loader.sh" send-telemetry   # loader by hand (update + scan)
```

## Reload (after editing the plist)

```bash
launchctl bootout   "$DOMAIN/$LABEL" 2>/dev/null
launchctl bootstrap "$DOMAIN" "$PLIST"
launchctl print     "$DOMAIN/$LABEL" | head -20
```

`config.json` changes need no reload — they're read at run time; just `kickstart`.
(The loader logs `launchctl load`/`unload`; the modern verbs above work regardless.)

## Uninstall

```bash
/bin/bash "$HOME/.stepsecurity/bin/stepsecurity-loader.sh" uninstall   # loader-managed (MDM)
"$HOME/.stepsecurity/bin/stepsecurity-dev-machine-guard" uninstall     # binary-managed

# Manual fallback:
launchctl bootout "$DOMAIN/$LABEL" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null
rm -f "$PLIST"

# Verify
launchctl list | grep stepsec                          # expect no output
ls -la "$PLIST" 2>&1                                    # expect not found
rm -rf "$HOME/.stepsecurity"                            # wipe local state (optional)
```

## Reinstall

```bash
/bin/bash "$HOME/.stepsecurity/bin/stepsecurity-loader.sh" install   # or re-push loader via MDM
launchctl print "$DOMAIN/$LABEL" | grep -iE 'state|last exit'
launchctl kickstart -k "$DOMAIN/$LABEL" && tail -n 20 "$LOGDIR/agent.log"
```

## Gotchas

- **config.json is rewritten every tick.** The loader's `write_config()` keeps only a fixed set (customer_id, api_endpoint, api_key, scan_frequency_hours + optional install_dir / max_execution_duration / scan toggles); any other hand-edited or profile-pushed field (e.g. `include_tcc_protected`) is wiped within one interval. Make it stick by editing the loader heredoc before deploy.
- **Runs only in a live GUI session.** No console user (login window, headless, SSH) → not loaded, won't fire; the loader's initial run errors `no_user`, and `launchctl … gui/<uid>` over SSH can return `Bootstrap failed: 5`.
- **TCC prompts are real.** It runs in the user's GUI session, so scanning Documents/Downloads/etc. pops permission dialogs; skipped by default. Grant Full Disk Access (PPPC profile), then set `include_tcc_protected`.
- **A wedged run blocks every tick.** The binary's lock file makes overlapping runs exit; a hung run holds the lock until the loader SIGKILLs processes older than `MAX_PROCESS_AGE_HOURS` on a later tick. Self-heals, but loses up to that window.
- **`StartInterval` quirks.** Missed fires during sleep coalesce into one run on wake; the timer also restarts on each load/login, so short sessions on a long interval can starve it.
- **`Bootstrap failed: 5`** most often means already loaded — `bootout` first, then `bootstrap`.
