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

| Step | Mechanism |
|------|-----------|
| Drop `.exe` to `C:\Program Files\StepSecurity\` | MSI standard `InstallFiles` |
| Write tenant config to `C:\ProgramData\StepSecurity\config.json` | Custom action invokes `.exe configure --non-interactive ...` |
| Register Windows scheduled task | Custom action invokes `.exe install` (which shells `schtasks.exe`) |
| On uninstall: remove scheduled task | Custom action invokes `.exe uninstall` |

**`powershell.exe` is never spawned.** All work flows: `msiexec` →
WiX's `WixQuietExec` (Util extension) → `stepsecurity-dev-machine-guard.exe`
→ `schtasks.exe`. This matters in environments where EDR blocks
PowerShell egress — a common enterprise posture.

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

## Upgrades

Each release ships a new MSI with the **same `UpgradeCode`** and a
higher `Version`. Windows Installer treats the install as a Major
Upgrade: silent uninstall of the old version (scheduled task removed
via our `uninstall` custom action) followed by install of the new one,
atomically. SCCM admins use the **supersedence** flow to point the new
Application at the old one — no scripting required.

The per-tenant `config.json` is **not** touched by upgrades — it lives
under `C:\ProgramData\StepSecurity\` which MSI doesn't manage. Tenants
stay configured across version bumps.

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
`String Equals <version>`; the rule survives ProductCode regen and
distinguishes versions across supersedence. See the Intune deployment
guide for the detection-rule walkthrough.

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
