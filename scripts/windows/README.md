# Portable Windows host provisioning

`Setup-Dmg.ps1` wraps the existing DMG MSI for a newly created session host. It verifies a local staged bundle, inspects actual installation state, installs/upgrades or performs supported task repair, and reports local readiness. The approved implementation is present; production rollout is **not accepted**. A lab-signed build of AVD source `a8b6059` was installed on a clean Windows multi-session VM: MSI succeeded, but readiness correctly failed because task setup grants Users Modify on the parent of machine configuration. Repair and MSI upgrade reproduce that permission. All readiness checks pass after a controlled lab-only ACL correction; that is not a successful unmodified installation. Correct the agent directory permissions and repeat native acceptance before rollout. AVD session, automatic updater and platform-admission acceptance remain unverified.

The platform selects the host, invokes setup after final naming and required join operations, and keeps non-ready hosts unavailable. This script has no Nerdio/Azure dependency, automatic master/clone detection, network downloads, recurring repair task, backend changes, or automatic reboot. The source image contains staged files only. Installed hosts update through the existing updater; staging files does not update the master.

## Stage and invoke

Use **64-bit Windows PowerShell 5.1, as SYSTEM, on x64 Windows**. PowerShell7 can run portable tests but is not the supported production entrypoint. Windows OpenSSH Client with `ssh-keygen -Y verify` support must already exist at `%SystemRoot%\System32\OpenSSH\ssh-keygen.exe`; no tool is downloaded or installed by setup.

Stage these explicitly selected local files:

```text
C:\StepSecuritySetup\
    Setup-Dmg.ps1
    Invoke-DmgProvisioningWorker.ps1
    Dmg.Provisioning.Execution.psm1
    Dmg.Provisioning.Policy.psm1
    Dmg.Provisioning.Windows.psm1
    agent.msi
    agent.msi.sha256.sig
    bootstrap.json
```

`agent.msi` is an illustrative local name for the exact release asset. Keep its matching `.sha256.sig` sidecar. No wildcard/latest lookup occurs. The pinned release key, namespace and identity match `internal/releasesig/releasesig.go`; Windows Authenticode and timestamp validation are also required. The MSI must match the x64 DMG product family and have version **>=1.19.0**. This is the source compatibility floor, not a claim that a signed1.19.0 release exists. The accessible signed v1.18.1 release verifies correctly but predates the AVD identity implementation and is rejected.

Protect the staging directory and files before invoking SYSTEM: owner SYSTEM/Administrators, no untrusted write/delete/ACL-control permissions, and no reparse-point ancestors. The MSI, sidecar and bootstrap input must also deny untrusted file reads. Paths must be explicit files on a local fixed drive; UNC, mapped network drives, alternate streams and unsafe quoting are rejected. Protect the script source itself through your deployment system: the entrypoint validates sibling code **before importing it**, but cannot establish the provenance of its own already-executing bytes. Do not place scripts in user profiles or writable share paths.

The bootstrap uses the existing DMG schema, including tenant/API credentials. Do not pass credentials as command-line properties. Use automatic multi-user identity or an explicit template containing both `{hostname}` and `{user}`; a literal shared device ID or fixed `user_id` is rejected. Automatic updates must remain enabled. Unknown keys fail rather than silently changing behavior. Configure required tenant values securely; do not use the test fixtures' dummy configuration for actual installation.

```powershell
& "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File 'C:\StepSecuritySetup\Setup-Dmg.ps1' `
    -MsiPath 'C:\StepSecuritySetup\agent.msi' `
    -ConfigPath 'C:\StepSecuritySetup\bootstrap.json' `
    -SignaturePath 'C:\StepSecuritySetup\agent.msi.sha256.sig' `
    -TimeoutSeconds 900 -MaxAttempts 3
$setupExit = $LASTEXITCODE
exit $setupExit
```

Run that action as SYSTEM on the selected host, not the imaging master. ExecutionPolicy is not a trust check; signatures and filesystem protection are separate. The caller's timeout must exceed the configured setup budget and allow process startup/result publication. Absence of a final response is failure, never readiness. Nerdio-specific invocation and admission behavior require separate validation in the customer's product/version.

## Outcomes

Stdout contains one JSON result on handled paths, with `schema_version`, `attempt_id`, `status`, `action`, `msi_version`, `running_version`, `checks`, `error_code`, `retryable`, `reboot_required`, `attempts`, `msi_exit_code`, `exit_code`, `result_path`, and `log_path`.

| Exit | Meaning | Calling platform |
| --- | --- | --- |
| 0 | Locally verified ready, including healthy no-op | May proceed with its own admission checks |
| 10 | Input/context/trust/preflight failure | Correct the cause; do not admit |
| 20 | Wrapper or Windows Installer busy | Arrange a bounded later retry |
| 30 | MSI or readiness/result-publication failure | Inspect safe diagnostics; do not admit |
| 40 | Deadline/unknown completion | Do not assume cancellation or start another installer |
| 50 | Restart required | Arrange a controlled restart, then rerun; do not admit yet |

The result does not claim backend telemetry arrived, that a user can log in, or that the next automatic update will succeed. Those are separate AVD acceptance checks. The runtime/default MSI profile is `C:\Program Files\StepSecurity` with configuration `C:\ProgramData\StepSecurity\config.json`; custom layouts fail closed.

## Mutation and recovery

A secured machine-wide mutex serializes wrappers. It does not replace Windows Installer's own locking or DMG's updater lock. Only MSI1618 (another installation is active) retries automatically: at most three attempts, with five- and ten-second delays. Each retry reobserves state before choosing its operation. Other native failures are terminal. The total budget defaults to900seconds (allowed30–3600); read-only workers are bounded to120seconds within the remaining budget.

Fresh install/upgrade uses `/i`, `/qn`, `/norestart`, `REBOOT=ReallySuppress`, and `BOOTSTRAPFILE=<private copy>`. Same-product task-only repair uses `/i REINSTALL=ALL REINSTALLMODE=omus` and omits bootstrap/config properties. No `/f`, uninstall, identity reset or updater-pointer rewrite. The MSI does not reload the bootstrap during same-product repair. MSI exit0 is followed by a fresh health inspection because its best-effort custom actions can fail.

MSI product version and currently running self-updated version are separate. Never downgrade either. A newer installed MSI cannot be repaired with older staged material. Tenant mismatch, product GUID/version mismatch, unsigned/damaged runtime, unsupported layout and ambiguous product registration require operator action. Only task drift in an otherwise healthy trusted installation is eligible for repair.

Before launching MSI, setup atomically writes a private operation journal. On timeout it leaves the installer alive, preserves uncertainty, and starts no replacement installer. A later invocation with a pending journal in the same boot returns40 even if the original client PID has disappeared: service-side installation may still be running. For this conservative first version, arrange a controlled reboot after investigating the operation; a changed boot permits fresh inspection. The script never reboots or deletes the journal to bypass the guard. MSI3010/1641 similarly returns50 and preserves that requirement until a subsequent boot. Invalid journal/boot identity fails closed. A crashed wrapper with no final result is not success.

## Private artifacts and diagnostics

Private files live under `%ProgramData%\StepSecurityProvisioning\<attempt_id>`, created with SYSTEM/Administrators access only. Each attempt copies and verifies its bundle before use. It keeps the MSI, bootstrap, sidecar, request files, result and allowlisted `events.jsonl`; the root's `operation.json` holds recovery state. These files are retained for diagnosis, including private credential-bearing bootstrap copies. Arrange a deliberate retention/credential-rotation policy; there is no automatic deletion in this version.

Public JSON/events never include config values, raw native error text or child output. There is deliberately no verbose MSI log because MSI/custom-action output can contain credentials. Event diagnostics record observation decisions, attempted operation, native exit code and final outcome. If deeper MSI troubleshooting is necessary, collect protected logs deliberately and treat them as sensitive. Hard termination may leave only the recovery journal and no final result. Result files never substitute for fresh readiness checks.

## Implementation and verification

- `Dmg.Provisioning.Policy.psm1`: strict configuration, version and readiness decisions.
- `Dmg.Provisioning.Windows.psm1`: protected runtime/manifest/signature/config checks, MSI registration/metadata and Task Scheduler inspection. It does not install or repair. Agent self-check can initialize its identity cache.
- `Dmg.Provisioning.Execution.psm1`: bounded processes, MSI arguments, recovery journal, mutex and retry orchestration.
- `Invoke-DmgProvisioningWorker.ps1`: bounded signature/COM/readiness operations; returns only safe fields, never configuration.
- `Setup-Dmg.ps1`: public input/context validation, protected staging, worker orchestration and result publication.

Portable tests (no Pester dependency) run with Windows PowerShell5.1 or PowerShell7:

```powershell
.\scripts\windows\tests\Test-DmgProvisioningPolicy.ps1
.\scripts\windows\tests\Test-DmgProvisioningWindows.ps1
.\scripts\windows\tests\Test-DmgProvisioningExecution.ps1
```

`Test-DmgProvisioningNative.ps1` additionally requires Windows/SYSTEM and an existing DMG installation; it reads registration/cached metadata and verifies untrusted-bundle rejection. `Test-DmgProvisioningSetupNative.ps1 -ReleaseMsi <signed1.18.1.msi> -ReleaseSignature <matching.sidecar>` exercises the public entrypoint as SYSTEM without installing: duplicate invocation, valid-but-old release rejection, tampered-package rejection, malformed config redaction a benign child surviving installer timeout policy, and writable sibling-module rejection before import. These are not fresh-install/repair/upgrade evidence.

Remaining rollout acceptance: actual supported signed MSI fresh install, healthy rerun, task repair, upgrade and interrupted installation; concurrent Alice/Bob scheduled scans; auto-update continuation; reusable master/reimage behavior; and platform admission gating. No successful production readiness claim is made until these gates pass.
