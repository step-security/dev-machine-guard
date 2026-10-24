# Windows self-update (MSI installs)

MSI installs (Intune, SCCM) keep themselves on the release your tenant
selects, without IT pushing a new MSI for every version. A small, stable
bootstrap launches whichever version is current. A separate SYSTEM task
downloads, verifies and switches versions, and rolls back a version that
crashes.

Packaging details (custom actions, the `AUTOUPDATE` property, upgrades and
the Intune detection rule) are in
[`packaging/windows/README.md`](../packaging/windows/README.md). For IT
admins (SCCM/Intune setup, network and proxy requirements, verifying a
device, and what each update event means), see the
[admin guide](windows-self-update-admin.md).

## Layout

```
C:\Program Files\StepSecurity\
  stepsecurity-dev-machine-guard-bootstrap.exe   MSI-owned, stable
  seed\<msi-version>\                            MSI-owned fallback payload
  versions\<v>\                                  updater-owned, immutable once in place
    stepsecurity-dev-machine-guard.exe
    stepsecurity-dev-machine-guard-task.exe
    dmg-linux
    manifest.json                                sha256 of every file
  state\state.json, update.lock, update.log      updater-owned
C:\ProgramData\StepSecurity\runs\<v>.json        one record per scan launch
HKLM\Software\StepSecurity\AgentVersion          MSI version (Intune detection)
HKLM\Software\StepSecurity\RunningVersion        version currently selected
```

- `versions\` and `state\` are owned by SYSTEM with a protected ACL:
  SYSTEM and Administrators full control, Users read and execute. The
  updater re-applies it on every run and reports any drift.
- The updater never touches the bootstrap, the seed or `AgentVersion`.
  The MSI touches `versions\` and `state\` only through two custom
  actions: on install, upgrade and repair, `adopt-seed` copies the seed
  into `versions\<seed>` and moves `current` forward to it if the seed is
  newer (never back), and a real uninstall removes both directories. A
  repair or upgrade therefore can't undo a self-update. The MSI stops
  running DMG processes and waits for its files to be free before any
  file action, and never reboots on its own (`REBOOT=ReallySuppress`;
  `msiexec /f` repairs ignore `/norestart`, see the packaging README). A
  failed
  upgrade that Windows Installer rolls back also undoes adopt-seed's
  change (it snapshots `state.json` first).

## Tasks

| Task | Runs as | Action |
|---|---|---|
| Scan (hourly/daily) and logon | Logged-in user | `bootstrap.exe run send-telemetry …` |
| `StepSecurity Dev Machine Guard (Update)` | SYSTEM, hourly + 15 min after boot | `bootstrap.exe update` |

`bootstrap.exe run` reads `state.json` once and launches `current`. If
that directory is missing or incomplete it falls back to `previous`, then
to the seed. Each launch is recorded in `runs\<v>.json`. A scan that ran
a fallback reports `update_pointer_invalid`.

`bootstrap.exe update` runs `agent.exe self-update --system` from the
confirmed version. While a new version is on probation it uses the
previous one, and after three consecutive updater failures it uses the
seed, so a broken updater can't freeze a device.

## One updater run

Every step can be interrupted at any point; the next run picks up from
the state on disk.

1. Take `state\update.lock`. Another updater already running → exit.
2. Clean up leftover staging, remove version directories nothing points
   at, re-apply ACLs, and refresh the device id from the hardware.
3. Check the version on probation (see below). This may roll back.
4. Ask the backend for the target: at most every 6 hours, or right after
   a probation closes. Stop if updates are off, the target is the current
   version, quarantined, below the minimum self-update version, or a
   probation is still open.
5. Stage the target in `versions\.staging-*`. Verification happens before
   anything is renamed into place:
   - every checksum's SSH signature is checked against the pinned release
     key, before any download;
   - sha256 is checked on each download (GitHub first, then the optional
     mirror);
   - both executables must have a valid, timestamped Authenticode
     signature from the same publisher as the running updater.
6. Run `agent.exe self-check` from the staged directory as SYSTEM (in a
   job, 60 s limit). A failure quarantines the version.
7. Wait (up to 10 minutes) until no scan is running, then switch `current`
   to the new version and start its probation.
8. Report the result.

## Health, rollback and quarantine

A new version is on probation until its scans prove it. The bootstrap
numbers every launch, and the probation counts launches numbered after
the switch (so clock changes can't hide runs). Each is classified:

- **Healthy:** the scan reached the backend (run-status `started`) and
  didn't crash or get killed by the watchdog.
- **Bad:** a crash (a Go panic, recovered or not, exits 2), "couldn't
  start the agent" (70) or a watchdog kill, whether or not the scan had
  posted `started`; or an exit before `started` with any code not listed
  as Neutral. The watchdogs count awake time only, so a laptop asleep past
  the limit is not killed; a kill means the scan really hung.
- **Neutral:** an exit 0 or 1 before `started` (offline, or skipped
  because another scan was running); an exit caused by the session
  ending (130, `0xC000013A` STATUS_CONTROL_C_EXIT, `0x40010004`
  DBG_TERMINATE_PROCESS); or a launch whose
  bootstrap died without recording an outcome (shutdown, logoff, the task
  time limit).

Outcome:

- One healthy run confirms the version (`update_confirmed`).
- Two bad runs with no healthy one roll back to the previous version
  (`update_rolled_back`, reason `bad_runs`).
- The probation window ends after 72 hours, or after 72 hourly update
  runs, whichever comes first. If by then there were six or more runs and
  none was healthy, the version rolls back (`inconclusive`) with a 7-day
  quarantine. With fewer runs, the version is self-checked again: a pass
  confirms it (`update_confirmed`, `smoke_only`), a failure rolls it back
  (`smoke_failed`).

Every other rollback, and a failed pre-switch self-check, quarantines the
version permanently on that device, so it is never staged again. A fix
ships as a new version.

## Turning it off

Install with `AUTOUPDATE=0` to stop taking new targets. The device stays
on whatever version is current at that moment, which may be a
self-updated version newer than the MSI's. The update task keeps
running (health checks and rollback still apply) and reports
`update_disabled` with the target it isn't taking, so the backend shows
how far behind the device is.

To go back to the MSI's own version, either re-enable self-update and
let the tenant's target bring it there, or uninstall and reinstall the
MSI (a fresh install starts from the seed). See the packaging README for
the `AUTOUPDATE` values and re-enabling.

## Version floor

The updater refuses any target older than the first release that
contains it (`minWindowsSelfUpdateVersion`, currently 1.18.0) and
reports `update_refused_floor`. A version below the floor has no updater
and would leave the device stuck. To put devices on an older release,
deploy that release's MSI instead.

## Device identity

Update events are sent under the device id the SYSTEM updater resolves:
the configured `device_id`, else the hardware serial (BIOS registry,
then WMI), else its own cached hardware id, else `MachineGuid`. It never
trusts the user-writable `C:\ProgramData\StepSecurity\device-id` file,
and only a hardware result is written back to it, so a transient probe
failure never changes the id the scans report.

## Events

Every outcome is posted to `run-status` with `status: "update"`, the
device id, the sending agent's version, `install_channel: "msi"`, and
`update_event`, plus `update_from` / `update_to` / `error_message` where
they apply:

`update_ok`, `update_confirmed`, `update_rolled_back`,
`update_download_failed`, `update_verify_failed`, `update_stage_failed`,
`update_health_failed`, `update_switch_failed`, `update_switch_deferred`,
`update_check_failed`, `update_refused_floor`, `update_disabled`,
`update_pointer_invalid`, `update_acl_drift`, `update_state_corrupt`,
`update_updater_failed`.

Each event is saved in `state.json` in the same write as the change it
reports, then sent. An event the backend rejects as invalid (HTTP 400 or
422) is dropped; any other failure is retried with a backoff of 1 hour,
doubling up to 24 hours. Up to 64 events are kept; beyond that the
oldest are dropped and counted. Repeated failures and refusals for the
same target are reported at most once per day.

## Existing fleets

Devices on an MSI older than the first self-updating release can't
update themselves. They need one final MSI push of a release that ships
the bootstrap; from then on they follow the tenant's target.
