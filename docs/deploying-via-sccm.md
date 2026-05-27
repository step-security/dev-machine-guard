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
SCCM → msiexec.exe → stepsecurity-dev-machine-guard.exe → schtasks.exe
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
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" /qn ^
  CUSTOMERID="acme-corp" ^
  APIENDPOINT="https://api.stepsecurity.io" ^
  APIKEY="sk_live_xxxxxxxxxxxxxxxx" ^
  SCANFREQUENCY=4 ^
  /l*v "C:\Windows\Temp\dmg-install.log"
```

| Property | Required | Description |
|----------|----------|-------------|
| `CUSTOMERID` | yes | Your StepSecurity tenant ID |
| `APIENDPOINT` | yes | StepSecurity backend URL (typically `https://api.stepsecurity.io`) |
| `APIKEY` | yes | Tenant API key from your StepSecurity dashboard |
| `SCANFREQUENCY` | no | Scheduled scan frequency in hours (default `4`) |

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
  "api_endpoint": "https://api.stepsecurity.io",
  "api_key": "sk_live_xxxxxxxxxxxxxxxx",
  "scan_frequency_hours": "4"
}
```

**Step 2**: deploy the MSI with the `BOOTSTRAPFILE` property pointing at
that path:

```cmd
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" /qn ^
  BOOTSTRAPFILE="C:\ProgramData\StepSecurity\bootstrap.json" ^
  /l*v "C:\Windows\Temp\dmg-install.log"
```

The API key never appears on the msiexec command line, so it stays out
of `AppEnforce.log` even with verbose logging enabled. The bootstrap
file can be ACL-restricted to SYSTEM + Administrators if you want
defense-in-depth.

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
   - Software version: matches the MSI you're deploying (e.g. `1.11.2`)
3. **Add Deployment Type** → **Windows Installer (`*.msi`)**
4. **Content**: point at the `.msi` file on a share that the
   Distribution Points can pull from
5. **Programs** tab:
   - **Installation program**: see Option A or B above
   - **Uninstall program**: SCCM auto-fills from the MSI `ProductCode`,
     usually `msiexec /x {PRODUCT-CODE} /qn`
6. **Detection method**: SCCM offers to use the MSI's product code by
   default — **accept it**. No custom script needed.
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
:: 1. The binary is on disk
dir "C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard.exe"

:: 2. The scheduled task is registered
schtasks /query /tn "StepSecurity Dev Machine Guard"

:: 3. The config landed where the scanner can read it
type "C:\ProgramData\StepSecurity\config.json"

:: 4. (Optional) trigger an immediate scan to confirm end-to-end
"C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard.exe" send-telemetry
```

The configured tenant should see the endpoint in the StepSecurity
dashboard within a few minutes.

## Upgrades

When a new version ships, **create a new Application** in SCCM with the
new MSI and mark it as **superseding** the previous Application:

1. New Application → **Supersedence** tab → **Add** → pick the old
   Application
2. Choose **Uninstall** for the old app (the new MSI's MajorUpgrade will
   do it atomically — but SCCM needs the supersedence link to track
   which endpoints to push the upgrade to)
3. Deploy the new Application to the same collection

On each endpoint:
- SCCM pushes the new MSI on its next policy cycle (default 60 min)
- Windows Installer recognizes the upgrade (same `UpgradeCode`, higher
  `Version`) → atomically uninstalls the old version (removes the
  scheduled task via our `uninstall` custom action), installs the new
  one (re-registers the task with the new binary)
- The per-tenant config at `C:\ProgramData\StepSecurity\config.json`
  is **preserved across upgrades** — tenant stays configured

## Uninstall

SCCM uninstall fires the `msiexec /x {ProductCode}` command. Our custom
action runs **before** file removal and calls
`stepsecurity-dev-machine-guard.exe uninstall`, which removes the
scheduled task via `schtasks /delete`. Then MSI removes the .exe and
empties `C:\Program Files\StepSecurity\`.

The config at `C:\ProgramData\StepSecurity\config.json` is **not
removed** by MSI (it lives outside the install scope). If you want a
clean uninstall:

```cmd
rmdir /s /q "C:\ProgramData\StepSecurity"
```

…as a post-uninstall cleanup step in SCCM, or via GPO.

## Troubleshooting

| Symptom | Likely cause | Where to look |
|---------|-------------|---------------|
| MSI exit code 1603 | Custom action failed (bad creds, schtasks denied) | `C:\Windows\Temp\dmg-install.log` (msiexec verbose log) |
| Scheduled task missing | `install` custom action skipped or failed | Same log; search for `RunInstallScheduledTask` |
| Endpoint not reporting to dashboard | Wrong API key / endpoint | `type C:\ProgramData\StepSecurity\config.json` |
| Endpoint config still under `%USERPROFILE%\.stepsecurity\` | MSI ran without elevation (shouldn't happen via SCCM) | Verify SCCM Application is set to "Install for system" |

When opening a support case, attach:

```
C:\Windows\Temp\dmg-install.log         (msiexec verbose log)
C:\ProgramData\StepSecurity\agent.log   (scanner output)
C:\ProgramData\StepSecurity\agent.error.log
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

> **Authenticode (Windows publisher signature)**: not yet applied. The
> Sigstore bundle above is build-provenance signing, which is a different
> system from Authenticode (the certificate-based signature Windows checks
> in UAC / SmartScreen / WDAC). If your environment requires
> Authenticode-signed installers as a deployment precondition, please open
> an issue — it's a tracked roadmap item.
