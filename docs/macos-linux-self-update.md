# macOS and Linux self-update (binary-scheduled installs)

Installs made with the current macOS and Linux loader register launchd or
systemd to run the agent binary directly on every tick; the loader script
runs once, at install, and never again. The binary therefore keeps itself on
the release your tenant selects: at the start of every scheduled run it
checks for the tenant's target version, verifies it, stages it next to
itself, smoke-tests it and swaps it in. The scan of that run still executes
the old image; the new version takes effect on the next scheduled run.

Older installs, where the scheduler runs the loader script and the script
re-downloads the binary on every tick, are not affected: the script keeps
owning updates there. Version-pinned installs never update either way.

The Windows MSI has its own updater, described in
[windows-self-update.md](windows-self-update.md).

## When a tick updates

A `send-telemetry` run performs one update tick, ahead of the run gate and
the scan, when all of the following hold:

- `config.json` carries `"auto_update": true`. The loader writes the key
  when it registers the scheduler to run the binary directly; pinned and
  script-scheduled installs never carry it.
- `STEPSEC_DISABLE_SELF_UPDATE` is not `1` in the agent's environment (the
  per-device kill switch).
- No other instance is mid-update (a second scan started by hand skips its
  tick).
- The directory holding the binary is writable by the account the scan runs
  as. A system-wide install owned by another account logs a debug line and
  does nothing.
- The run is not a WSL guest scan started by the Windows agent (the host
  passes `--wsl-host-serial` and `--wsl-distro-id`). The `dmg-linux` binary
  under the Windows install is updated by the Windows MSI updater.

The check runs at most every 6 hours (`last_check_at` in the state file),
and at once after the running version changed.

## What one tick does

1. **Check.** `GET /v1/{customer}/developer-mdm-agent/latest-binary` with
   `os`, `arch`, `current`, `reason` and the tenant's update policy
   (`update_lag_behind`, `update_cooldown_hours` from config.json), exactly
   as the loader asked. The response names one version, its sha256 and the
   SSHSIG signature over that checksum.
2. **Refuse what cannot be installed.** A target below the macOS/Linux
   self-update floor (the first release that updates itself) is refused: a
   binary-scheduled install that landed such a version would never update
   again. A version that failed its smoke test in the last 7 days is not
   staged again.
3. **Verify before downloading.** The SSHSIG over the checksum must verify
   against the pinned release key. Nothing is downloaded otherwise.
4. **Compare.** If the sha256 of the running binary equals the signed
   checksum, the install is current.
5. **Stage.** The release asset (`stepsecurity-dev-machine-guard-<v>-darwin`
   or `…-linux_<arch>`, from GitHub Releases or the tenant's
   `update_mirror_url`) is downloaded into a temporary directory next to the
   binary, on the same file system, and its sha256 checked against the signed
   checksum. A download needs about 180 MiB free on that volume.
6. **Smoke test.** The staged binary runs `self-check` with a 60 s limit,
   with this install's own `--config` and `--install-dir`, and must report
   the target version, a loadable enterprise configuration and a device id.
   A failure quarantines the version for 7 days; a timeout is retried at the
   next check.
7. **Switch.** The running binary is kept as `<binary>.prev` (a hard link),
   then the staged file replaces the binary with one atomic rename. A crash
   at any point leaves either the old or the new binary, never a partial
   one. `.current_version` in the install directory is refreshed.
8. **Confirm.** The next scheduled run executes the new version. Its own
   tick posts `update_confirmed` and removes `<binary>.prev`. A run that was
   already executing the old image when the switch happened (or that waited
   on the update lock behind the switching run) recognises the installed file
   by its recorded sha256 and leaves the pending switch, its backup and its
   confirmation to the new version.

Every failure is logged on stderr (`agent.error.log` under launchd, the
journal under systemd) with a `self-update:` prefix, reported as an update
event, and never fails the run: the scan proceeds on the current binary.

Because the tick runs before the scan, a release that breaks scans still
reaches the updater on its next tick. Pinning the tenant to the previous
version in the dashboard moves such devices back without touching them.

## Files

```
<install dir>/                        ~/.stepsecurity, or install_dir from config.json
  bin/stepsecurity-dev-machine-guard         the binary launchd/systemd runs
  bin/stepsecurity-dev-machine-guard.prev    replaced binary, until the new one confirms
  self-update.json                           last check, current/previous version and the installed file's sha256, quarantine
  .current_version                           installed version (loader-compatible marker)
```

`self-update.json` is advisory: a missing or corrupt file only costs an
earlier re-check. Uninstalling with the loader removes all of these.

## Update events

Each tick reports what it did through the run-status API (status `update`,
`install_channel` `loader`), so the device page shows the same event names as
Windows:

| Event | Meaning |
|---|---|
| `update_ok` | A new version was installed; it runs from the next scheduled run. |
| `update_confirmed` | The new version ran its first scheduled tick. |
| `update_check_failed` | `latest-binary` could not be reached or answered an error. |
| `update_refused_floor` | The tenant's target predates the macOS/Linux self-update; the device stays put. |
| `update_verify_failed` | The signature over the checksum, or the downloaded file's sha256, did not verify. |
| `update_download_failed` | GitHub Releases and the mirror both failed to serve the asset. |
| `update_stage_failed` | No room, no writable staging directory, or the running binary could not be hashed. |
| `update_health_failed` | The staged binary failed its `self-check` (`smoke_failed: …`); quarantined for 7 days. |
| `update_switch_failed` | The rename over the running binary failed. |

Repeated failures of the same kind for the same target are reported once a
day.

## Turning it off

- Per device: `stepsecurity-dev-machine-guard configure --auto-update=false`
  (writes `"auto_update": false`), or `STEPSEC_DISABLE_SELF_UPDATE=1` in the
  scheduler's environment (`EnvironmentVariables` in the launchd plist,
  `Environment=` in the systemd unit).
- Per tenant: the dashboard's update policy (pin, lag behind, cooldown)
  decides which version `latest-binary` names; the device follows it.

## Rolling back by hand

Until the new version confirms, the previous binary is still there:

```sh
cd ~/.stepsecurity/bin
mv -f stepsecurity-dev-machine-guard.prev stepsecurity-dev-machine-guard
```

The next tick notices it runs a version other than the one it installed,
restarts its state from the running version and checks for the tenant's
target again, so pin the tenant first if the rollback should stick.

## Verifying a device

```sh
stepsecurity-dev-machine-guard version
stepsecurity-dev-machine-guard self-check     # {"version":…,"device_id":…,"config_ok":true}
cat ~/.stepsecurity/self-update.json
grep self-update ~/.stepsecurity/agent.error.log | tail
```
