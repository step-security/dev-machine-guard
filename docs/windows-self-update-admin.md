# Windows self-update: guide for IT admins (SCCM / Intune)

This guide is for IT teams that deploy Dev Machine Guard to Windows
endpoints with **Microsoft Configuration Manager** (SCCM / MECM) or
**Intune**. It covers what changes with self-update, what the network
and endpoints need, how to set up the deployment, how to control and
verify updates, and how to troubleshoot.

How the updater works internally (state files, verification steps,
probation rules) is described in
[`windows-self-update.md`](windows-self-update.md). The general SCCM
setup (credentials, `config.json` permissions, signature verification)
is in [`deploying-via-sccm.md`](deploying-via-sccm.md).

## What changes in 1.18.0

- **One last MSI push.** Devices on an MSI older than 1.18.0 can't update
  themselves. Deploy the 1.18.0 (or newer) MSI once, the same way you
  deploy any upgrade. It replaces the older version in place and keeps
  the tenant configuration and the device identity, so each device keeps
  its existing record in the StepSecurity console.
- **Then the devices update themselves.** A SYSTEM scheduled task
  downloads, verifies and switches to the version StepSecurity releases
  for your tenant. You don't need a new SCCM Application or Intune app
  for every release.
- **No user prompts.** Updates run in the background as SYSTEM. Users
  need no admin rights and see no windows, UAC prompts or notifications.
- **No reboots.** Neither an update nor the MSI (install, upgrade, repair
  or uninstall) restarts the machine. A version switch waits until no
  scan is running.

## How it works

1. The MSI installs a small, stable **bootstrap**, a **seed** copy of the
   agent (the MSI's own version) and three scheduled tasks.
2. The scan tasks run as the logged-in user and start, through the
   bootstrap, whichever version is current.
3. The **Update** task runs as SYSTEM every hour. About every 6 hours it
   asks the StepSecurity API which version your tenant should run.
4. It downloads that version into its own `versions\<version>\` folder,
   verifies the signatures, self-tests it, and then makes it current.
5. A new version that crashes or hangs in its first scans is rolled back
   automatically and never retried on that device. Every outcome is
   reported to the console.

## Requirements

### Network endpoints

The Update task runs as **SYSTEM**, so these must be reachable for the
machine account, not just for logged-in users (HTTPS, port 443):

| Endpoint | Used for |
|---|---|
| `<api-host>` (the host in your `APIENDPOINT`) | The target version check (about every 6 hours) and update reports. Scans already use this host. |
| `github.com` | Release downloads, from `https://github.com/step-security/dev-machine-guard/releases/download/v<version>/...` |
| `release-assets.githubusercontent.com` | GitHub redirects release downloads to this host |
| Your mirror, if configured | Only when the GitHub download fails (see [Download mirror](#download-mirror-optional)) |

Each update downloads three files: the agent, the launcher and the Linux
agent used for WSL scans (about 30 MB together).

### TLS inspection

The updater checks server certificates against the Windows certificate
store. If a proxy or firewall inspects TLS, its root certificate must be
in the **Local Computer** Trusted Root store; the SYSTEM account doesn't
see per-user certificate stores.

Inspection doesn't weaken the update's integrity: every file is checked
against StepSecurity's signed checksum and its Authenticode signature,
whatever the network path. A proxy that blocks, rewrites or "sanitizes"
executable downloads makes every update fail (`update_download_failed`
or `update_verify_failed`). Let the release downloads through unchanged.

Signature checks don't need extra network access: the updater does not
make online certificate revocation checks.

### Proxy

The updater picks a proxy per request, in this order:

1. **Environment variables**, set machine-wide (the SYSTEM account doesn't
   read user variables): `HTTPS_PROXY` for HTTPS requests, `HTTP_PROXY`
   for HTTP, and `NO_PROXY` for hosts that go direct. If `HTTPS_PROXY`
   is set, it alone decides how HTTPS requests go.

   ```cmd
   setx HTTPS_PROXY "http://proxy.example.com:8080" /M
   setx NO_PROXY "localhost,127.0.0.1,.corp.example.com" /M
   ```

   `NO_PROXY` accepts host names (a name also matches its subdomains,
   with or without a leading dot), IP addresses, CIDR ranges and `*`.

2. Otherwise, the **WinHTTP machine proxy**, with its bypass list
   (`<local>` and `*` wildcards are honoured):

   ```cmd
   netsh winhttp set proxy proxy-server="proxy.example.com:8080" bypass-list="<local>;*.corp.example.com"
   netsh winhttp show proxy
   ```

3. Otherwise, a direct connection.

PAC files and WPAD auto-detection are not used. Proxies that require
user authentication (NTLM, Kerberos) are not supported for the updater:
allow the endpoints above for the machine without authentication.

### Disk space

Before it downloads, the updater needs free space of three times the
current version's size plus 50 MB (about 140 MB today) on the system
drive. It keeps only the versions it may need: the current one, the
previous one (for rollback), a copy of the MSI's seed version and, for
up to a day, a downloaded version waiting to be switched to. Older
version folders are deleted automatically.

### Download mirror (optional)

If devices can't reach GitHub, host the release files on an HTTPS server
you control and add `update_mirror_url` to the bootstrap file (see
below):

```json
"update_mirror_url": "https://mirror.example.com/dmg"
```

The updater requests `<update_mirror_url>/<version>/<release file name>`
(no `v` before the version), for example
`https://mirror.example.com/dmg/1.19.0/stepsecurity-dev-machine-guard-1.19.0-windows_amd64.exe`.
Mirror the three files for each version and architecture you run:
`stepsecurity-dev-machine-guard-<version>-windows_<arch>.exe`,
`stepsecurity-dev-machine-guard-task-<version>-windows_<arch>.exe` and
`stepsecurity-dev-machine-guard-<version>-linux_<arch>`, where `<arch>`
is `amd64` or `arm64`. The URL must be `https://`, with no user name,
password, query or fragment. The mirror is tried only when the GitHub
download fails, and its files go through the same signature checks, so
the mirror itself needs no special trust.

The bootstrap file is applied on install and on each MSI upgrade, so a
mirror added later reaches existing devices with their next MSI upgrade.

## SCCM, step by step

### 1. Prepare the bootstrap file

Pass the tenant credentials in a **bootstrap file** (`BOOTSTRAPFILE`)
rather than inline (`APIKEY=...`). SCCM stores the deployment type's
command line in the site database, and `AppEnforce.log` on every device
logs it verbatim, so an inline API key ends up in both.

Deploy this file to every endpoint (Group Policy Preferences, a
configuration item, or any file distribution you already use), for
example at `C:\ProgramData\StepSecurity\bootstrap.json`:

```json
{
  "customer_id": "<your-tenant>",
  "api_endpoint": "https://<api-host>",
  "api_key": "<your-api-key>",
  "scan_frequency_hours": "4"
}
```

- Restrict the file to SYSTEM and Administrators.
- **Keep the file in place.** Every MSI install and upgrade that passes
  `BOOTSTRAPFILE` reads it; if it's missing, the install fails (1603) and
  is rolled back. Keys in the file override the device's existing
  settings; settings that aren't in the file (such as the auto-update
  setting) are kept.

### 2. Create the Application

1. **Software Library → Application Management → Applications → Create
   Application**.
2. Choose **Windows Installer (\*.msi file)** and point at
   `stepsecurity-dev-machine-guard-<version>-x64.msi` (or `-arm64.msi`)
   on a share your distribution points can read. SCCM reads the
   ProductCode from the MSI.
3. Software version: the MSI version, e.g. `1.18.0`.

### 3. Deployment type: programs

**Installation program:**

```cmd
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" /qn /norestart BOOTSTRAPFILE="C:\ProgramData\StepSecurity\bootstrap.json" /l*v "C:\Windows\Temp\dmg-install.log"
```

Add `AUTOUPDATE=0` to opt these devices out of self-update (see
[Controlling updates](#controlling-updates)).

**Uninstall program** (SCCM fills in the ProductCode):

```cmd
msiexec /x {PRODUCT-CODE} /qn /norestart /l*v "C:\Windows\Temp\dmg-uninstall.log"
```

**Repair program:** use this exact form:

```cmd
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" REINSTALL=ALL REINSTALLMODE=omus /qn /norestart /l*v "C:\Windows\Temp\dmg-repair.log"
```

Don't use `msiexec /f...` for repairs. A `/f` repair ignores every
command-line property, including `/norestart` and `AUTOUPDATE`. From
1.18.0 the MSI itself suppresses restarts and stops Dev Machine Guard
before it replaces files, so even a `/f` repair no longer reboots. But
MSIs up to 1.17.0 could restart the machine without a prompt when a `/f`
repair ran during a scan, and `/f` can't change the auto-update setting.
The repair re-creates the three scheduled tasks and restores the seed if
needed. It never moves a self-updated device back to the MSI's version.

### 4. Detection method

Either rule works and stays stable while the device updates itself:

- **The MSI ProductCode** (SCCM's default for an MSI deployment type).
  Accept it.
- Or a **registry** rule: `HKEY_LOCAL_MACHINE\SOFTWARE\StepSecurity`,
  value `AgentVersion`, String, **Equals** the MSI version (e.g.
  `1.18.0`), 64-bit.

`AgentVersion` always names the installed MSI. The version the device is
actually running is in `RunningVersion`. Never detect on `RunningVersion`
or on an executable's file version: both change with every self-update,
SCCM would then see the app as missing and reinstall it over and over.

### 5. User experience and deployment

- **Installation behavior:** Install for system. **Logon requirement:**
  Whether or not a user is logged on. **Visibility:** Hidden.
- **Required** is recommended for the fleet: SCCM installs at the
  deadline and reinstalls the app if it's removed. **Available** lets
  users install from Software Center (no admin rights needed); use it for
  pilots.
- Deploy to a pilot collection first, then expand.

### 6. Later MSIs: supersedence

You don't need a new Application for each release. Ship a newer MSI only
when you want to (for example, so that new devices start on a recent
version, or to move devices onto a newer seed). When you do:

1. Create a new Application for the new MSI, with the same programs and
   detection as above.
2. **Supersedence** tab → **Add** → pick the previous Application's
   deployment type. Leave **Uninstall** cleared: the new MSI replaces the
   old one itself (a Windows Installer major upgrade) and keeps the
   device's self-update state.
3. Deploy the new Application to the same collection, Required, with
   **Automatically upgrade any superseded versions of this application**
   selected.

Once the new Application is deployed, SCCM shows the superseded
Application's own deployment as **Not Applicable** on those devices and
no longer runs it. That's expected.

If a device has already updated itself past the new MSI's version, the
upgrade still succeeds and the device keeps its newer version; the MSI's
version only becomes the fallback.

### 7. Pushing an older MSI

An MSI never downgrades a device:

- An MSI older than the **installed** MSI, deployed as a separate
  Application (not in a supersedence chain), fails with **1603**: "A
  newer version of StepSecurity Dev Machine Guard is already installed."
- An MSI that is older than the version the device **runs**, but not
  older than the installed MSI, installs or repairs normally, and the
  device keeps its newer self-updated version.

To move devices to an older release, contact StepSecurity support (see
[Controlling updates](#controlling-updates)).

## Intune

The Intune package (`.intunewin`) wraps the same MSI with `install.cmd`
and `uninstall.cmd`, which already pass `/qn /norestart` and log to
`C:\ProgramData\StepSecurity\install.log` / `uninstall.log`. Packaging
details are in [`packaging/windows/README.md`](../packaging/windows/README.md).

- **Install command:** `install.cmd BOOTSTRAPFILE="C:\ProgramData\StepSecurity\bootstrap.json"`
  (add `AUTOUPDATE=0` to opt out). **Uninstall command:** `uninstall.cmd`.
  **Install behavior:** System.
- **Detection rule:** Registry, `HKEY_LOCAL_MACHINE\SOFTWARE\StepSecurity`,
  value `AgentVersion`, String comparison **Equals** the MSI version,
  not associated with a 32-bit app. Don't use `RunningVersion` or the
  file version (see [Detection method](#4-detection-method)).
- **Supersedence** for a newer MSI: set **Uninstall previous version** to
  **No**, for the same reason as SCCM. The new MSI upgrades the old one
  in place.

## Controlling updates

The `AUTOUPDATE` MSI property sets the device's auto-update setting. It
has no default:

| `AUTOUPDATE` | Effect (install, upgrade, repair with `/i ... REINSTALL=ALL`) |
|---|---|
| `0` (or `false`) | Self-update off |
| `1` (or `true`) | Self-update on |
| not set | The current setting is kept; a new install starts with self-update on |

**Opting out** (`AUTOUPDATE=0`):

- The device stays on the version it runs at that moment, which may be a
  self-updated version newer than the MSI's. It doesn't go back to the
  MSI's version.
- The Update task keeps running: health checks and automatic rollback of
  a bad version still apply.
- The device reports `update_disabled` ("Auto update off" in the console)
  with the version it is not taking, at most once a day per version, so
  you can see how far behind it is.

**Re-enabling:** redeploy with `AUTOUPDATE=1`, or repair in place:

```cmd
msiexec /i "stepsecurity-dev-machine-guard-<version>-x64.msi" REINSTALL=ALL REINSTALLMODE=omus AUTOUPDATE=1 /qn /norestart
```

**The opt-out is sticky.** The setting lives in
`C:\ProgramData\StepSecurity\config.json`, which upgrades and uninstalls
keep. So an opted-out device stays opted out across MSI upgrades
(including a failed, rolled-back upgrade), repairs, and even an uninstall
followed by a reinstall, unless that install passes `AUTOUPDATE=1`. To
reset a device to the default (on), either pass `AUTOUPDATE=1` on its
next install, or delete `C:\ProgramData\StepSecurity\config.json` after
uninstalling and before reinstalling.

**Release pacing, pausing and rollback** are controlled by StepSecurity
for your tenant: which version your devices take, how fast a new release
reaches them, pausing a release, and moving the fleet back to an earlier
release. Contact StepSecurity support to change them. Devices pick up a
change at their next check, within about 6 hours. A device never takes a
version older than 1.18.0, the first self-updating release.

## Verify a device

### Scheduled tasks

| Task | Runs as | What it does |
|---|---|---|
| `StepSecurity Dev Machine Guard` | Logged-in user | The periodic scan (every `SCANFREQUENCY` hours), started through the bootstrap |
| `StepSecurity Dev Machine Guard (Logon)` | Logged-in user | The same scan at logon |
| `StepSecurity Dev Machine Guard (Update)` | SYSTEM | The updater: hourly (with up to 10 min random delay) and 15 min after boot; 30 min time limit; also runs on battery |

```cmd
schtasks /query /tn "StepSecurity Dev Machine Guard"
schtasks /query /tn "StepSecurity Dev Machine Guard (Logon)"
schtasks /query /tn "StepSecurity Dev Machine Guard (Update)"
```

To run an update check now instead of waiting for the next hour, run the
Update task:

```cmd
schtasks /run /tn "StepSecurity Dev Machine Guard (Update)"
```

### Folders

```
C:\Program Files\StepSecurity\
  stepsecurity-dev-machine-guard-bootstrap.exe   the bootstrap the tasks start (from the MSI)
  seed\<msi-version>\                            the MSI's own copy of the agent: the fallback
  versions\<version>\                            versions the updater installed, one folder each
  state\state.json                               which version is current
  state\update.log                               the updater's log
C:\ProgramData\StepSecurity\
  config.json                                    tenant config and the auto-update setting
  runs\<version>.json                            a record of each scan launch per version
```

`versions\` and `state\` are owned by SYSTEM; users can read but not
change them. The updater re-applies these permissions on every run.

### Registry

```powershell
Get-ItemProperty -Path 'HKLM:\Software\StepSecurity' | Select-Object AgentVersion, RunningVersion
```

- `AgentVersion`: the installed **MSI** version (what SCCM and Intune
  detect).
- `RunningVersion`: the version the device currently **runs**. After a
  self-update it is higher than `AgentVersion`; that's expected.

### state.json and the update log

`C:\Program Files\StepSecurity\state\state.json` (readable without admin
rights) names the `current` version and, after an update, the `previous`
one that a rollback would return to. While a new version is being
proven, a `probation` entry names it. A version that failed on this
device is listed under `quarantine` and is never installed there again.

`C:\Program Files\StepSecurity\state\update.log` has one line per
updater step, with timestamps (it rotates to `update.log.1` past 1 MB).

### In the StepSecurity console

- The device page has a **Self-update** card: the running version, the
  latest update event with its reason, and a timeline of recent update
  events (newest first).
- In the device list, a cue next to the agent version shows a device's
  update outcome from the last 24 hours: a red **⚠** label (for example
  "⚠ Rolled back") for events that need attention, or **↑ Updated** after
  a successful update.
- A successful update shows up as **Updated** (`update_ok`), then a scan
  on the new version, then **Update confirmed** (`update_confirmed`).
- A version change made by an **MSI** (an upgrade that installs a newer
  version than the device ran) has no update event; it shows as the new
  agent version on the device's next scan.

## Troubleshooting by console event

Each update outcome is reported with an event name, the versions it went
from and to, and a reason. The console shows a label; the raw event name
appears on hover.

| Console label (event) | What it means | What to do |
|---|---|---|
| Updated (`update_ok`) | The device switched to the new version. With reason `seed_adopted`, it moved to a newer version from an MSI. | Nothing. Expect "Update confirmed" after the next successful scan. |
| Update confirmed (`update_confirmed`) | The new version completed a scan and is kept. Reason `smoke_only`: no scan ran in the probation window, so it was confirmed by a self-test. | Nothing. |
| Rolled back (`update_rolled_back`) | The new version failed on this device and the device went back to the version in "to". It won't take that version again. Reasons: `bad_runs` (crashed, hung or couldn't start twice), `smoke_failed` (failed its self-test), `pointer_invalid` (its files were damaged), `inconclusive` (no successful scan in 72 hours; retried after 7 days). | One device: check for software that kills or blocks processes in `C:\Program Files\StepSecurity\versions\`. Many devices: contact StepSecurity support. |
| Download failed (`update_download_failed`) | The release files couldn't be downloaded from GitHub or the mirror. | Allow `github.com` and `release-assets.githubusercontent.com` for the machine (see [Requirements](#requirements)), or configure a mirror. Retried at the next check. |
| Verification failed (`update_verify_failed`) | A downloaded file failed a signature, checksum or publisher check. Nothing was installed. | One device: look for a proxy, TLS inspection or security tool that alters downloads. Many devices: contact StepSecurity support. |
| Staging failed (`update_stage_failed`) | The new version couldn't be written to disk (space, permissions). Reason `av_deleted`: antivirus deleted the running version's files three times in a day; re-installing it is paused for 24 hours. | Free disk space (see [Disk space](#disk-space)). For `av_deleted`, exclude `C:\Program Files\StepSecurity\` from file quarantine. |
| Health check failed (`update_health_failed`) | The new version failed its self-test before the switch. The device stays on its version and won't take that one again. | Check that the device's configuration is complete (`config.json`). Many devices: contact StepSecurity support. |
| Switch failed (`update_switch_failed`) | The new version was ready but the switch couldn't be saved. | Check disk health and free space. Retried automatically. |
| Switch deferred (`update_switch_deferred`) | A scan was running at four update runs in a row, so the switch kept waiting. | Usually nothing: it switches at the first update run with no scan running. If it repeats, check for scans that never finish. |
| Update check failed (`update_check_failed`) | The device couldn't get its target version from the StepSecurity API. | Check the machine's access to `<api-host>`, the proxy settings and the API key in `config.json`. Reported at most once a day. |
| Below version floor (`update_refused_floor`) | The device was offered a version older than 1.18.0 and refused it. | Contact StepSecurity support. |
| Auto update off (`update_disabled`) | Self-update is off on this device (`AUTOUPDATE=0`); the event names the version it isn't taking. | Expected for opted-out devices. To re-enable, see [Controlling updates](#controlling-updates). |
| Version pointer invalid (`update_pointer_invalid`) | A scan couldn't start the current version and ran a fallback (the previous version or the MSI's seed). The reason names the cause, e.g. `state_missing` or `current_missing:<version>`. | Usually fixed by the next update run. If it repeats, check the Update task exists and runs; repair the MSI. |
| Permissions repaired (`update_acl_drift`) | Something changed the permissions on `versions\` or `state\`; the updater restored them. | If it repeats, find the tool or Group Policy changing permissions under `C:\Program Files\StepSecurity\`. |
| Update state corrupt (`update_state_corrupt`) | `state.json` was missing or unreadable and was rebuilt. | Once: nothing. Repeated: check disk health and tools that delete files under `C:\Program Files\StepSecurity\state\`. |
| Updater failing (`update_updater_failed`) | The updater in the current version failed three times in a row, and the MSI's copy took over. | Contact StepSecurity support with the device's `update.log`. |

**No update events at all** from a device usually means it still runs an
MSI older than 1.18.0 (it needs the final MSI push), the Update task is
missing (check with `schtasks /query`, then repair the MSI), or the
device can't reach `<api-host>`.

**The last event is "Updated" and nothing since:** the new version is on
probation. The device makes no update checks until a scan on the new
version succeeds (then "Update confirmed" follows at the next update
run) or the probation ends. Check that scans are running.

## Troubleshooting install issues

### 1603 "A newer version ... is already installed" and phantom MSI registrations

This message means Windows Installer found a newer Dev Machine Guard
product registered on the device. Usually that's real (see
[Pushing an older MSI](#7-pushing-an-older-msi)). But a **failed** MSI
install or upgrade run by SCCM can leave a **phantom** registration
behind: the product is registered as "advertised" without being
installed. It isn't in Programs and Features, yet it blocks any install
of a lower version.

Detect it in an elevated PowerShell. The GUID is the x64 MSI's
UpgradeCode; for the arm64 MSI use `{99C4A108-6A71-4006-8AA7-F3D14DA045A9}`:

```powershell
$wi = New-Object -ComObject WindowsInstaller.Installer
foreach ($pc in @($wi.RelatedProducts('{65AE0FC0-2070-4F40-B0CA-413637F94121}'))) {
  "$pc ProductState=$($wi.ProductState($pc))"
}
```

- `ProductState=5`: installed. A healthy device has exactly one.
- `ProductState=1`: advertised only, a **phantom**.

Remove each phantom by its ProductCode, then redeploy:

```cmd
msiexec /x {PHANTOM-PRODUCT-CODE} /qn /norestart
```

If `msiexec /x` fails, contact StepSecurity support with the output
above and the MSI log.

### Other 1603 failures

The MSI log names the failing step. Common causes: the `BOOTSTRAPFILE`
path doesn't exist or isn't readable by SYSTEM (search the log for
`--from-file`), or the credentials are incomplete (`api_key is
required`). A failed install or upgrade is rolled back completely: the
device keeps the version, the tasks and the settings it had.

### 3010 (restart required)

3010 means the install succeeded but a file was in use and Windows will
finish replacing it at the next restart. The MSI never restarts the
machine itself, and Dev Machine Guard doesn't need that restart to run.
It can happen on the upgrade from an older MSI that doesn't yet stop
Dev Machine Guard before replacing files. SCCM and Intune treat 3010 as
a soft reboot and follow your client restart settings.

### Logs to collect for a support case

| Log | Where |
|---|---|
| MSI verbose log | The `/l*v` path in your command line (e.g. `C:\Windows\Temp\dmg-install.log`); Intune: `C:\ProgramData\StepSecurity\install.log` |
| SCCM client logs | `C:\Windows\CCM\Logs\AppEnforce.log` (the command line and exit code), `AppDiscovery.log` (detection), `AppIntentEval.log` (applicability, supersedence) |
| Updater log | `C:\Program Files\StepSecurity\state\update.log` and `update.log.1` |
| Updater state | `C:\Program Files\StepSecurity\state\state.json` |
| Versions | `Get-ItemProperty -Path 'HKLM:\Software\StepSecurity'` output |

Plus the device id from the console. `AppEnforce.log` contains the full
install command line: another reason to keep the API key in the
bootstrap file.

## Uninstall

Uninstalling (the SCCM uninstall deployment, `msiexec /x {PRODUCT-CODE}`
or Intune's `uninstall.cmd`) stops all Dev Machine Guard processes and
removes:

- the three scheduled tasks;
- everything under `C:\Program Files\StepSecurity\`: the bootstrap, the
  seed, all `versions\` and `state\` (including `update.log`);
- the `AgentVersion` and `RunningVersion` registry values.

It keeps `C:\ProgramData\StepSecurity\`: `config.json` (the tenant
configuration, including the API key and the auto-update setting),
`device-id` (so a reinstalled device keeps its record in the console),
the scan records in `runs\` and the scan logs. That's what lets an
uninstall and reinstall pick up where it left off. To remove everything,
for example when decommissioning a device, delete the folder after the
uninstall:

```cmd
rmdir /s /q "C:\ProgramData\StepSecurity"
```

## FAQ

**Does self-update ever reboot the machine?**
No. Updates switch versions between scans, and the MSI sets
`REBOOT=ReallySuppress` and stops Dev Machine Guard before it touches
files. Use the repair command above (not `/f`), which also matters for
devices still on 1.17.0 or older.

**Will users see prompts?**
No. The Update task runs as SYSTEM in the background with no window,
no UAC prompt and no notification.

**Do users need admin rights?**
No. Updates run as SYSTEM. Scans run as the logged-in user, as before.

**How much bandwidth does it use?**
One small API request about every 6 hours, and about 30 MB per new
version, downloaded once per device. Devices don't download versions
they already have.

**Can a device be downgraded?**
An MSI never downgrades a device. StepSecurity can move your tenant back
to an earlier release (1.18.0 or newer) if a release has a problem;
devices then switch down at their next check, through the same verified
path. A version that crashed or failed its self-test on a device is
never installed on it again; a fix ships as a new version.

**What if SCCM repairs the app during an update or a scan?**
The repair stops Dev Machine Guard first, then finishes normally, without
a reboot, and keeps the current version. An interrupted update continues
at the next hourly run. A scan that was running is stopped and runs again
at its next scheduled time; in the console that one scan shows as started
without a finished status.

**What about offline devices?**
They keep running and scanning on their current version. The update
check and any pending reports are retried when the device is back online
(reports are kept on the device until they are delivered). One case to
know: a device that goes offline right after switching to a new version
can't prove that version. If it has six or more scans in 72 hours and
none reaches the backend, it goes back to the previous version (reason
`inconclusive`) and tries the new one again after 7 days.

**What about machines with several users?**
Self-update is per machine: one installed version serves every user. The
scan tasks run as whichever user is logged on. A version switch waits
until no scan is running, and if scans keep running it retries every
hour.

**What if a release is bad?**
A version that crashes, hangs or fails its self-test is rolled back on
each device after at most two failed scans, reported as "Rolled back",
and never retried there. StepSecurity can also pause a release or move
tenants back.

**Can I keep using my SCCM/Intune app for a while?**
Yes. Keep the 1.18.0 (or newer) app deployed so new devices get it.
Detection stays satisfied on self-updated devices, so SCCM and Intune
don't reinstall anything.
