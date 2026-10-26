# MSI packaging

This directory holds the WiX 4 manifest used to wrap the Windows binary
into an MSI for SCCM / Intune / Group Policy deployments.

## Local build

Requires **WiX 4** plus the `WixToolset.Util.wixext` extension (the
manifest uses `WixQuietExec` from the Util extension to drive custom
actions in deferred context):

```bash
dotnet tool install --global wix --version 4.0.5
wix extension add --global WixToolset.Util.wixext/4.0.5
```

WiX 4 nominally supports macOS / Linux as well as Windows, but at the
4.0.5 version we pin, the non-Windows hosts have bugs in path-handling
that break our manifest (Directory/@Name validation). The release
workflow in this repo runs the MSI build on `windows-latest` for that
reason; local development on Windows is the supported path.

Then from the repo root:

```bash
# Build the x64 MSI (the build-windows-amd64 .exe is built as a dependency).
make build-msi-amd64
# produces dist/stepsecurity-dev-machine-guard-<version>-x64.msi
```

For arm64 (less common but supported):

```bash
make build-msi-arm64
# produces dist/stepsecurity-dev-machine-guard-<version>-arm64.msi
```

(Each MSI target has its own arch-specific `build-windows*` prerequisite — the
top-level `build-windows` target is hardcoded amd64 only, so don't try
`GOARCH=arm64 make build-windows`. Use the dedicated targets above.)

## What the MSI does

Install layout (the MSI owns the bootstrap, the seed, `AgentVersion` and
the three scheduled tasks; the SYSTEM updater owns `versions\` and
`state\`):

```
C:\Program Files\StepSecurity\
  stepsecurity-dev-machine-guard-bootstrap.exe        stable task entrypoint
  seed\<msi-version>\                                 read-only fallback
  versions\<v>\                                      self-update versions
      (each holds stepsecurity-dev-machine-guard.exe,
       stepsecurity-dev-machine-guard-task.exe, dmg-linux;
       versions\<v>\ also a manifest.json)
  state\state.json                                    which version is current
```

| Step | Mechanism |
|------|-----------|
| Drop the bootstrap and `seed\<version>\` | MSI standard `InstallFiles` |
| Write tenant config to `C:\ProgramData\StepSecurity\config.json` | `seed\<version>\stepsecurity-dev-machine-guard.exe configure --non-interactive ...` (install / upgrade with credentials) |
| Create `versions\` + `state\` (SYSTEM-owned, Users read-only), copy the seed into `versions\<version>`, point `current` at it unless a newer self-updated version is already current | `bootstrap.exe adopt-seed` (install, upgrade, repair; never fails the MSI) |
| (Re)create the 3 scheduled tasks | `seed\<version>\stepsecurity-dev-machine-guard.exe install` (install, upgrade **and repair**) |
| Real uninstall: delete the tasks, stop running DMG processes, remove `versions\`, `state\`, `RunningVersion` | `seed\<version>\stepsecurity-dev-machine-guard.exe uninstall` (first retires the device in the dashboard when `config.json` has `retire_on_uninstall`; skipped during a major upgrade, which therefore never retires; failures never block removal) |

Scheduled tasks:

| Task | Principal | Action |
|------|-----------|--------|
| `StepSecurity Dev Machine Guard` (periodic) and `… (Logon)` | INTERACTIVE | `bootstrap.exe run send-telemetry --install-dir="C:\ProgramData\StepSecurity"` |
| `StepSecurity Dev Machine Guard (Update)` | SYSTEM | `bootstrap.exe update` — hourly (10 min random delay) and 15 min after boot |

**`powershell.exe` is never spawned.** All work flows: `msiexec` →
WiX's `WixQuietExec` (Util extension) → the bootstrap or the seed agent
→ `schtasks.exe`. This matters in environments where EDR blocks
PowerShell egress — a common enterprise posture.

Optional properties `DEVICEID` (device identity template, e.g.
`{hostname}-{user}`) and `RETIREONUNINSTALL=1` are forwarded to
`configure --device-id` / `--retire-on-uninstall`; both are also accepted
as `device_id` / `retire_on_uninstall` keys in a `BOOTSTRAPFILE`. See
`docs/deploying-on-virtual-desktops.md`.

## Self-update and `AUTOUPDATE`

MSI installs update themselves: the SYSTEM update task stages a newer
signed release into `versions\<v>\` and switches `state.json` to it; the
next scan runs it, and a version that fails its health check is rolled
back. Self-update never changes `AgentVersion` or the ProductCode.

Self-update is on by default. The `AUTOUPDATE` property controls it and
has no default value:

| `AUTOUPDATE` | Effect (install, upgrade and repair) |
|--------------|--------------------------------------|
| `0`, `f`, `F`, `false`, `FALSE`, `False` | `"auto_update": false` in the SYSTEM-owned machine config |
| `1`, `t`, `T`, `true`, `TRUE`, `True` | `"auto_update": true`: turns self-update back on |
| unset | the setting is left as it is (a fresh install uses the default: on) |
| any other value | not applied; `configure` logs `--auto-update must be true or false` in the MSI log and the install continues |

Any non-empty value runs `configure --non-interactive --auto-update=<value>`,
which accepts exactly the values Go's `strconv.ParseBool` accepts.

```cmd
msiexec /i stepsecurity-dev-machine-guard-<version>-x64.msi /qn ^
  BOOTSTRAPFILE="C:\ProgramData\StepSecurity\bootstrap.json" AUTOUPDATE=0
```

An opted-out device's update task keeps running and reports
`update_disabled` with the version it is not taking. To re-enable,
redeploy with `AUTOUPDATE=1`, or repair in place with
`msiexec /i <msi> /qn REINSTALL=ALL REINSTALLMODE=omus AUTOUPDATE=1`
(`msiexec /f` ignores properties, so a plain `/f` repair can't change it).

## How tenants pass credentials

Two equivalent paths — pick one in your SCCM Application's install
command:

### Inline (simplest)

```cmd
msiexec /i stepsecurity-dev-machine-guard-<version>-x64.msi /qn ^
  CUSTOMERID="acme-corp" ^
  APIENDPOINT="https://api.stepsecurity.io" ^
  APIKEY="sk_..." ^
  SCANFREQUENCY=4 ^
  /l*v "%TEMP%\dmg-install.log"
```

Caveat: the API key appears in `AppEnforce.log` on every endpoint when
`/l*v` is enabled. SCCM's default logging usually keeps it out, but
verbose troubleshooting will surface it.

### Pre-staged bootstrap file (recommended for prod)

Drop a JSON config via GPO / Intune File preferences first:

```json
{
  "customer_id": "acme-corp",
  "api_endpoint": "https://api.stepsecurity.io",
  "api_key": "sk_...",
  "scan_frequency_hours": "4"
}
```

…at `C:\ProgramData\StepSecurity\bootstrap.json`, then deploy the MSI:

```cmd
msiexec /i stepsecurity-dev-machine-guard-<version>-x64.msi /qn ^
  BOOTSTRAPFILE="C:\ProgramData\StepSecurity\bootstrap.json"
```

Key never traverses the msiexec command line — survives `/l*v` logging
clean.

## Repairs and reboots

The MSI never restarts the machine on its own: it sets
`REBOOT=ReallySuppress`, so a file that is still in use ends the install
with exit code 3010 ("restart required"), never a restart. Before any file
action it also stops running Dev Machine Guard processes and waits until
none holds an MSI-owned file, so a repair or upgrade that overlaps a scan
or an update tick completes normally (exit 0).

`msiexec /f…` repairs ignore every command-line property, including
`/norestart` and `AUTOUPDATE`. For SCCM/Intune repairs use:

```cmd
msiexec /i stepsecurity-dev-machine-guard-<version>-x64.msi REINSTALL=ALL REINSTALLMODE=omus /qn /norestart
```

## Upgrades

Each release ships a new MSI with the **same `UpgradeCode`** and a
higher `Version`. Windows Installer treats the install as a Major
Upgrade: silent removal of the old version followed by install of the
new one, atomically. The old version's uninstall custom action is
**skipped** during an upgrade (`REMOVE="ALL" AND NOT
UPGRADINGPRODUCTCODE`), so a successful upgrade keeps the self-update
state, and the new version's `install` replaces the tasks. If an upgrade
fails late and Windows Installer rolls it back, adopt-seed's rollback
action restores `state.json` to its pre-upgrade content and removes the
`versions\<seed>` directory the upgrade created, so the device keeps
running the version it had. Known gap: if the failure happens after the
old product's tasks were replaced, re-running the install (or a repair)
restores them. SCCM admins use the **supersedence** flow to point the new
Application at the old one — no scripting required.

An MSI upgrade never downgrades a self-updated device: if the device
already runs a newer version than the MSI's seed, `current` is kept and
the seed only becomes the fallback.

Devices on an MSI older than the first self-updating release need **one
more MSI push** (the first bootstrap MSI); after that they update
themselves.

The per-tenant `config.json` in `C:\ProgramData\StepSecurity\` is not an
MSI component, so an upgrade never removes it and tenants stay configured
across version bumps. It is rewritten only when the upgrade passes
credentials (`configure`) or `AUTOUPDATE`.

## Detection method

SCCM auto-derives the detection rule from the MSI's `ProductCode`. No
custom script needed. The `UpgradeCode` is stable across versions; the
`ProductCode` rotates per build (WiX generates it automatically).

For Intune Win32 deployments, ProductCode-based detection breaks under
supersedence because each rebuild's regenerated ProductCode does not
match the previous app entry. The MSI writes a stable
`HKLM\Software\StepSecurity\AgentVersion` registry value
(component `VersionRegistry`) set to the MSI's `ProductVersion` on
every install. Intune detection rules read that value with
`String Equals <msi version>`; the rule survives ProductCode regen and
distinguishes versions across supersedence. See the Intune deployment
guide for the detection-rule walkthrough, and the
[Windows self-update admin guide](../../docs/windows-self-update-admin.md#intune)
for detection, supersedence, the opt-out and troubleshooting with
self-update.

Detection rule:

| Field | Value |
|-------|-------|
| Rule type | Registry |
| Key path | `HKEY_LOCAL_MACHINE\SOFTWARE\StepSecurity` |
| Value name | `AgentVersion` |
| Detection method | String comparison, **Equals** `<msi version>` (e.g. `1.18.0`) |
| Associated with a 32-bit app on 64-bit clients | No |

**Self-update does not break this rule.** `AgentVersion` always names the
installed MSI, not the running version: the updater records what it runs
in `RunningVersion` (inventory only) and never writes `AgentVersion`. A
self-updated device therefore stays "detected" for the MSI it got, Intune
never reinstalls it, and **supersedence** with a newer MSI still works
(the new app's rule names the new MSI version). Don't build detection on
the binary's file version or on `RunningVersion`: both change with
self-update and would cause a reinstall loop.

## GUIDs

The `UpgradeCode`s in `Product.wxs` are **load-bearing constants** —
never change them. They identify the product family across all current
and future versions:

| Platform | UpgradeCode |
|----------|-------------|
| x64      | `65AE0FC0-2070-4F40-B0CA-413637F94121` |
| arm64    | `99C4A108-6A71-4006-8AA7-F3D14DA045A9` |

If either ever changes, every existing deployment will see the new MSI
as an unrelated product and refuse to upgrade.
