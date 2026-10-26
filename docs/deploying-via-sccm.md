# Deploying Dev Machine Guard via Microsoft Configuration Manager (SCCM)

This guide is for IT admins deploying Dev Machine Guard to a fleet of
Windows endpoints through **Microsoft Configuration Manager** (formerly
SCCM, now part of Microsoft Intune family as MEMCM / ConfigMgr).

## What ships

- `stepsecurity-dev-machine-guard-<version>-x64.msi` (Windows on Intel/AMD)
- `stepsecurity-dev-machine-guard-<version>-arm64.msi` (Windows on ARM)

SCCM consumes them natively as **Application** deployment type "Windows
Installer (`*.msi`)". Detection rule and uninstall command are auto-derived
from the MSI `ProductCode` — no scripting required on your side. Each MSI
ships with a Sigstore (cosign) bundle alongside it for supply-chain
verification (see [Signature verification](#signature-verification) below).

## Why MSI and not a script

Many enterprise environments block PowerShell from making outbound
network calls via EDR. Our MSI install/upgrade/uninstall flows **never
spawn PowerShell**. The chain is:

```
SCCM → msiexec.exe → stepsecurity-dev-machine-guard[-bootstrap].exe → schtasks.exe
```

Custom actions run inside `msiexec`'s process tree as **deferred** actions
in SYSTEM context (`Execute="deferred" Impersonate="no"`). Deferred is
required because immediate actions execute during MSI script-building,
before the binary is actually on disk. They invoke our binary via
WiX's `WixQuietExec` (from `WixToolset.Util.wixext`); the binary then
shells out to `schtasks.exe` for task registration. Nothing in the
install path touches `powershell.exe`.

## Two ways to pass tenant credentials

| | **Inline properties** | **Pre-staged bootstrap file** |
|---|---|---|
| **Set up** | One step (MSI deploy) | Two steps (drop config, then MSI deploy) |
| **API key in logs** | Appears in `AppEnforce.log` if `/l*v` is on | Never on command line — safe under any logging |
| **Multi-tenant** | One Application per tenant (different command line) | One Application; per-tenant config via GPO/Intune File preferences |
| **Recommended** | OK for small / lab deployments | **Yes for production** |

### Option A — Inline properties

Use this in the SCCM Application's **Installation program** field:

```cmd
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" /qn /norestart ^
  CUSTOMERID="acme-corp" ^
  APIENDPOINT="https://agent.api.stepsecurity.io" ^
  APIKEY="sk_live_xxxxxxxxxxxxxxxx" ^
  SCANFREQUENCY=4 ^
  /l*v "C:\Windows\Temp\dmg-install.log"
```

| Property | Required | Description |
|----------|----------|-------------|
| `CUSTOMERID` | yes | Your StepSecurity tenant ID |
| `APIENDPOINT` | yes | StepSecurity backend URL (typically `https://agent.api.stepsecurity.io`) |
| `APIKEY` | yes | Tenant API key from your StepSecurity dashboard |
| `SCANFREQUENCY` | no | Scheduled scan frequency in hours (default `4`) |
| `DEVICEID` | no | Device identity template: a literal id, or `{serial}` `{hostname}` `{user}` tokens (e.g. `{hostname}-{user}` for pooled virtual desktops). Empty keeps the hardware serial. See [deploying-on-virtual-desktops.md](deploying-on-virtual-desktops.md) |
| `RETIREONUNINSTALL` | no | `1` makes `msiexec /x` retire the device in the dashboard before removing the scheduled task (a major upgrade never retires) |

### Option B — Pre-staged bootstrap file (recommended)

**Step 1**: deploy a JSON config to every target endpoint via GPO File
Preferences, Intune Settings Catalog → Files, or any other config
distribution channel. Path:

```
C:\ProgramData\StepSecurity\bootstrap.json
```

Contents:

```json
{
  "customer_id": "acme-corp",
  "api_endpoint": "https://agent.api.stepsecurity.io",
  "api_key": "sk_live_xxxxxxxxxxxxxxxx",
  "scan_frequency_hours": "4",
  "device_id": "{hostname}-{user}",
  "retire_on_uninstall": true
}
```

`device_id` and `retire_on_uninstall` are optional; they are the bootstrap
equivalents of the `DEVICEID` / `RETIREONUNINSTALL` properties above and
matter for ephemeral or shared machines — see
[deploying-on-virtual-desktops.md](deploying-on-virtual-desktops.md).

**Step 2**: deploy the MSI with the `BOOTSTRAPFILE` property pointing at
that path:

```cmd
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" /qn /norestart ^
  BOOTSTRAPFILE="C:\ProgramData\StepSecurity\bootstrap.json" ^
  /l*v "C:\Windows\Temp\dmg-install.log"
```

The API key never appears on the msiexec command line, so it stays out
of `AppEnforce.log` even with verbose logging enabled. The bootstrap
file can be ACL-restricted to SYSTEM + Administrators if you want
defense-in-depth.

Keep the bootstrap file in place after the install: every later MSI
upgrade that passes `BOOTSTRAPFILE` reads it again, and fails (1603,
rolled back) if it's missing. Keys in the file override the device's
existing settings; settings not in the file (such as the self-update
opt-out) are kept.

### A note on the persisted `config.json` and multi-user machines

Either deployment path above writes the resolved config — including
`api_key` in plaintext — to `C:\ProgramData\StepSecurity\config.json`
on each endpoint. This is required because the scheduled task runs
under the **logged-in user's** context (see "Why MSI and not a script"
above for rationale) and needs to read the config at scan time.

The installer hardens the file's ACL on write to:

- `NT AUTHORITY\SYSTEM` — Full Control
- `BUILTIN\Administrators` — Full Control
- `BUILTIN\Users` — Read

Inheritance is disabled. So any logged-in user CAN read the API key
(necessary for the scanner), but cannot modify it. On a **single-user
developer workstation** this is the expected security posture.

On a **shared multi-user machine** (e.g., a kiosk, a lab workstation,
RDS host) this means every interactive user can read each others'
tenant API key. If that's not acceptable for your environment:

- Use the `BOOTSTRAPFILE` path and tighten the bootstrap file's ACL
  yourself (the installer only manages `config.json`'s ACL)
- Or scope deployment to single-user machines via SCCM collection
  requirements
- DPAPI-backed storage is on our roadmap; open a feature request to
  register interest

## SCCM Application setup, step by step

1. **Software Library → Applications → Create Application**
2. **Manually specify the application information**:
   - Name: `StepSecurity Dev Machine Guard`
   - Publisher: `StepSecurity`
   - Software version: matches the MSI you're deploying (e.g. `1.18.0`)
3. **Add Deployment Type** → **Windows Installer (`*.msi`)**
4. **Content**: point at the `.msi` file on a share that the
   Distribution Points can pull from
5. **Programs** tab:
   - **Installation program**: see Option A or B above
   - **Uninstall program**: SCCM auto-fills from the MSI `ProductCode`;
     use `msiexec /x {PRODUCT-CODE} /qn /norestart`
   - **Repair program**: `msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" REINSTALL=ALL REINSTALLMODE=omus /qn /norestart`
     (see [Repairs](#repairs))
6. **Detection method**: SCCM offers to use the MSI's product code by
   default — **accept it**. No custom script needed. A registry rule on
   `HKLM\SOFTWARE\StepSecurity`, `AgentVersion` equals the MSI version,
   works too. Never detect on `RunningVersion` or a file version: both
   change when the device updates itself.
7. **User Experience** tab:
   - **Installation behavior**: Install for system
   - **Logon requirement**: Whether or not a user is logged on
   - **Installation program visibility**: Hidden
8. **Requirements** tab:
   - For x64 MSI: `Operating system → Windows → All Windows 10/11 (64-bit)
     and Windows Server 2016+ (64-bit)`
   - For arm64 MSI: same but ARM64 variant
9. **Deploy** to a test collection first (5-10 machines), then expand.

## Validating a successful deployment

After SCCM reports the install as complete, on a target endpoint:

```cmd
:: 1. The bootstrap is on disk
dir "C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard-bootstrap.exe"

:: 2. The scheduled tasks are registered (scan, logon scan, updater)
schtasks /query /tn "StepSecurity Dev Machine Guard"
schtasks /query /tn "StepSecurity Dev Machine Guard (Logon)"
schtasks /query /tn "StepSecurity Dev Machine Guard (Update)"

:: 3. The config landed where the scanner can read it
type "C:\ProgramData\StepSecurity\config.json"

:: 4. (Optional) trigger an immediate scan to confirm end-to-end
schtasks /run /tn "StepSecurity Dev Machine Guard"
```

The configured tenant should see the endpoint in the StepSecurity
dashboard within a few minutes.

## Self-update

From 1.18.0, MSI installs **update themselves**: a SYSTEM scheduled task
downloads, verifies and switches to the version StepSecurity releases for
your tenant, without user prompts or reboots, and rolls back a version
that fails. Devices on an older MSI need one final push of the 1.18.0 (or
newer) MSI; after that you don't need a new Application per release.

Network and proxy requirements, the `AUTOUPDATE=0` opt-out, how to verify
a device and what each update event in the console means are covered in
the [Windows self-update guide for IT admins](windows-self-update-admin.md).

## Repairs

Use this repair command (it's also what Software Center's **Repair**
runs when you set it as the deployment type's repair program):

```cmd
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" REINSTALL=ALL REINSTALLMODE=omus /qn /norestart
```

Don't use `msiexec /f...`: it ignores every command-line property,
including `/norestart` and `AUTOUPDATE`. MSIs up to 1.17.0 could restart
the machine without a prompt when a `/f` repair ran during a scan; from
1.18.0 the MSI suppresses restarts itself and stops Dev Machine Guard
before replacing files. A repair re-creates the scheduled tasks and never
moves a self-updated device back to the MSI's version.

## Upgrades

With self-update you only need a new MSI when you want one (for example
so that new devices start on a recent version). To roll one out,
**create a new Application** in SCCM with the new MSI and mark it as
**superseding** the previous Application:

1. New Application → **Supersedence** tab → **Add** → pick the old
   Application. Leave **Uninstall** cleared: the new MSI's major upgrade
   replaces the old version itself and keeps the device's self-update
   state.
2. Deploy the new Application to the same collection, with **Automatically
   upgrade any superseded versions of this application** selected.

On each endpoint:
- SCCM pushes the new MSI on its next policy cycle (default 60 min)
- Windows Installer recognizes the upgrade (same `UpgradeCode`, higher
  `Version`) and replaces the old version in one transaction. The old
  version's uninstall action is skipped during an upgrade, and the new
  version re-registers the scheduled tasks
- If the device already runs a newer self-updated version than the new
  MSI, it keeps it; the MSI's version becomes the fallback
- The per-tenant config at `C:\ProgramData\StepSecurity\config.json`
  is **preserved across upgrades** — tenant stays configured
- Once the new Application is deployed, SCCM reports the superseded
  Application's deployment as **Not Applicable** on those devices

An MSI never downgrades a device: an MSI older than the installed one,
deployed outside the supersedence chain, fails with 1603 ("A newer
version of StepSecurity Dev Machine Guard is already installed").

## Uninstall

SCCM uninstall fires the `msiexec /x {ProductCode}` command. Our custom
action runs **before** file removal and calls the agent's `uninstall`,
which removes the three scheduled tasks via `schtasks /delete`, stops
running Dev Machine Guard processes, and deletes the self-update
`versions\` and `state\` folders and the `RunningVersion` registry value.
Then MSI removes the remaining files and empties
`C:\Program Files\StepSecurity\`.

The config at `C:\ProgramData\StepSecurity\config.json` is **not
removed** by MSI (it lives outside the install scope), so a reinstall
keeps the tenant configuration, the device identity and the self-update
opt-out. If you want a clean uninstall:

```cmd
rmdir /s /q "C:\ProgramData\StepSecurity"
```

…as a post-uninstall cleanup step in SCCM, or via GPO.

## Troubleshooting

| Symptom | Likely cause | Where to look |
|---------|-------------|---------------|
| MSI exit code 1603 | Custom action failed (bad creds, missing bootstrap file, schtasks denied) | `C:\Windows\Temp\dmg-install.log` (msiexec verbose log) |
| 1603 "A newer version … is already installed" | A newer DMG MSI is installed, or a failed SCCM install left a phantom "advertised" registration | [Phantom MSI registrations](windows-self-update-admin.md#1603-a-newer-version--is-already-installed-and-phantom-msi-registrations) |
| Exit code 3010 | A file was in use; replaced at the next restart (the MSI never restarts by itself) | Nothing to do; SCCM follows your client restart settings |
| Device not updating / update errors in the console | Network, proxy, opt-out | [Windows self-update guide](windows-self-update-admin.md#troubleshooting-by-console-event) |
| Scheduled task missing | `install` custom action skipped or failed | Same log; search for `RunInstallScheduledTask` |
| Endpoint not reporting to dashboard | Wrong API key / endpoint | `type C:\ProgramData\StepSecurity\config.json` |
| Endpoint config still under `%USERPROFILE%\.stepsecurity\` | MSI ran without elevation (shouldn't happen via SCCM) | Verify SCCM Application is set to "Install for system" |

When opening a support case, attach:

```
C:\Windows\Temp\dmg-install.log         (msiexec verbose log)
C:\Windows\CCM\Logs\AppEnforce.log      (SCCM command line and exit code)
C:\ProgramData\StepSecurity\agent.log   (scanner output)
C:\ProgramData\StepSecurity\agent.error.log
C:\Program Files\StepSecurity\state\update.log   (self-update log)
```

## Signature verification

Each MSI release ships with a **Sigstore (cosign) bundle** for provenance
— it proves the artifact was built by this repo's GitHub Actions release
workflow from a tagged commit, with no out-of-band tampering. To verify
before deploying to your fleet:

```bash
# In a Linux/macOS environment with cosign installed
cosign verify-blob \
  --bundle stepsecurity-dev-machine-guard-<version>-x64.msi.bundle \
  --certificate-identity-regexp 'https://github.com/step-security/dev-machine-guard/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  stepsecurity-dev-machine-guard-<version>-x64.msi
```

> **Authenticode (Windows publisher signature)**: the MSIs and the Windows
> `.exe`s are Authenticode-signed with an RFC 3161 timestamp, in addition
> to the Sigstore bundle above (build provenance, a separate system). The
> self-updater also requires every version it installs to carry a valid,
> timestamped Authenticode signature from the same publisher as the
> version already installed.
