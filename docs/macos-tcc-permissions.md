# macOS TCC Permissions

This guide covers how Dev Machine Guard handles macOS **Transparency,
Consent, and Control** (TCC) — Apple's per-app permission system that
gates access to user data folders (`~/Documents`, `~/Downloads`,
`~/Desktop`, `~/Pictures`, Mail/Messages/Safari libraries, iCloud
Drive, removable volumes, etc.) — and what to configure on a fleet
deployment to scan those folders without prompting users.

## Default behavior — skip everything TCC-protected

The agent ships with **safe defaults**: every scan (`send-telemetry`
from launchd and direct CLI runs alike) **skips** the well-known
macOS TCC-protected directories. Two effects:

- The agent **never triggers a TCC permission popup**. End users see no
  "stepsecurity-dev-machine-guard would like to access files in your
  Documents folder" dialog.
- Anything that lives under a TCC-protected path (a Node.js project in
  `~/Documents/code`, a venv under `~/Desktop/scratch`, an `.npmrc` in
  `~/Downloads`) is **not scanned**.

For most fleets this is the right trade-off — developer code typically
lives under `~/code`, `~/src`, `~/work`, etc., not in `~/Documents`.
Customers who **do** want full coverage should grant the agent Full
Disk Access via an MDM-pushed PPPC profile (recommended) or via System
Settings on each machine, then flip the `include_tcc_protected` config
to `true`.

### What gets skipped

The skip list is hard-coded against the well-known TCC categories on
modern macOS (anchored at the logged-in user's `$HOME`):

```
~/Desktop                  ~/Library
~/Documents                ~/.Trash
~/Downloads
~/Pictures                 /Volumes/.timemachine*  (Time Machine local
~/Movies                                            snapshots, prefix match)
~/Music
~/Public
```

`~/Library` is skipped wholesale rather than per-subpath. Every macOS
release adds new Apple-managed subtrees behind new TCC services —
Sonoma added "App Management" / "Data from other apps" for arbitrary
`<app>/Data` containers, Sequoia hardened Photos / Media Library /
Movies, Tahoe expanded Media Library to cover
`~/Library/Application Support/com.apple.avfoundation/` — so a curated
allowlist of `Library/X` entries goes stale on every upgrade and
prompts start firing again at end users. `~/Library` is the wrong
place for developer projects, lockfiles, or `.npmrc` files anyway. The
detectors that DO need to read specific paths under `~/Library`
(JetBrains plugins at `~/Library/Application Support/JetBrains/...`,
Claude desktop MCP config, pip global config) use targeted
`ReadDir`/`ReadFile` calls that don't consult the skipper, so they
keep working unchanged.

If a search dir is explicitly named (`--search-dirs ~/Documents`) the
walk root itself is honored — the skip only applies to TCC paths
encountered as descendants of the walked root.

### What is NOT skipped by default — network volumes

One TCC class is deliberately **not** in the list above: **Network
Volumes** (`kTCCServiceSystemPolicyNetworkVolumes`). macOS classifies
any non-local mount this way, which includes SMB/NFS/AFP shares *and*
the mounts container runtimes expose the guest filesystem through:

| Runtime | Typical mount | Filesystem |
|---|---|---|
| **OrbStack** | `~/OrbStack` (containers, volumes, machines) | virtiofs |
| **Docker Desktop** | file-sharing mounts | virtiofs / gRPC-FUSE |
| **Colima / Lima** | share mounts | virtiofs / sshfs |

The agent walks these by default, and that walk is the point: it is
what inventories the npm and Python packages living **inside dev
containers** — supply-chain surface no other part of the scan reaches.
The cost is one TCC prompt per user, the first time a scan walks a
container mount:

> **"stepsecurity-dev-machine-guard" would like to access files on a
> network volume.**

**What the user should click: Allow.** Denying doesn't break the scan —
the walk gets `EPERM` on that mount and the rest of the run completes
normally — it just drops the container inventory. The decision is
remembered per user; the prompt does not come back.

Admins have two ways to keep it off developers' screens, and they are
mutually exclusive:

1. **Pre-answer it with a PPPC profile** (allow *or* deny — both
   suppress the prompt). This is the better option: `Allowed=true`
   keeps full coverage with no user interaction. It requires a fixed
   system-wide install path — see
   [Network Volumes pre-approval](#network-volumes-pre-approval-recommended-for-fleets)
   below.
2. **Turn the walk off** with `include_network_volumes: false`. No
   prompt, no profile, no fixed install path needed — and no container
   inventory. This is the escape hatch for fleets already deployed
   per-user that can't migrate the install path.

## Toggling the behavior

Three places can set the toggle. CLI flag wins over persistent config
wins over the default.

### CLI flag (single run)

```bash
# Default — TCC paths skipped, no popups
stepsecurity-dev-machine-guard --pretty --enable-npm-scan

# Opt in to scanning TCC paths for this run
stepsecurity-dev-machine-guard --pretty --enable-npm-scan --include-tcc-protected

# Explicit skip (even if config says otherwise)
stepsecurity-dev-machine-guard --pretty --enable-npm-scan --no-include-tcc-protected

# Skip network volumes (container mounts) for this run — no prompt,
# no container inventory
stepsecurity-dev-machine-guard --pretty --enable-npm-scan --no-include-network-volumes

# Walk them (the default) even if config says otherwise
stepsecurity-dev-machine-guard --pretty --enable-npm-scan --include-network-volumes
```

The two toggles are independent, and their defaults are opposites:
`include_tcc_protected` defaults to **skip**, `include_network_volumes`
defaults to **walk**.

When network volumes are skipped, the run logs exactly which mounts it
gave up so the coverage loss is visible in fleet logs rather than
silent:

```
WARN  macOS TCC: skipping 1 network volume(s) — packages inside container
      mounts will not be inventoried. Pass --include-network-volumes to
      scan them: [/Users/alice/OrbStack]
```

### Persistent config (`~/.stepsecurity/config.json`)

```json
{
  "customer_id": "your-customer-id",
  "api_endpoint": "https://api.stepsecurity.io",
  "api_key": "step_…",
  "scan_frequency_hours": "4",
  "include_tcc_protected": true,
  "include_network_volumes": false
}
```

Omit `include_network_volumes` entirely to keep the default (walk them).
Only `false` has an effect; `true` is the default and is written by
`configure` as an omitted field.

The agent reads this on every run. On an MDM-deployed fleet the
StepSecurity loader script (the `.sh` file the dashboard generates for
each customer) writes `config.json` on every periodic tick, so to roll
out `include_tcc_protected` across a fleet either edit the loader
script's `write_config()` heredoc before deploying it via MDM, or have
admins write the field into `~/.stepsecurity/config.json` directly on
each box (e.g., via a Configuration Profile or `defaults`-style file
deployment).

## Granting the agent Full Disk Access (so it can actually scan TCC paths)

Setting `include_tcc_protected: true` only tells the agent **not to
self-censor**. macOS still enforces TCC: without a grant, reads in
protected dirs will silently fail with `EACCES`. For the agent to
actually see the contents, it needs Full Disk Access (FDA).

The same PPPC mechanism pre-answers the Network Volumes prompt
(`SystemPolicyNetworkVolumes`), which is a separate service from FDA —
granting Full Disk Access does **not** cover it. Both are in the ready-made
profile at
[`packaging/macos/stepsecurity-dev-machine-guard-tcc.mobileconfig`](../packaging/macos/stepsecurity-dev-machine-guard-tcc.mobileconfig).

There are two ways to grant FDA.

### Option A — MDM-pushed PPPC profile (recommended for fleets)

Apple's **Privacy Preferences Policy Control (PPPC)** payload lets MDM
admins pre-approve specific binaries for specific TCC services. The
end user sees nothing; the grant is in place the moment the device
checks in with the MDM.

This is the only way to grant FDA at scale without per-user clicks.

#### Inputs you need

- **The install path of the binary.** By default the loader installs at
  `~/.stepsecurity/bin/stepsecurity-dev-machine-guard`, which is
  per-user. Because PPPC's `Identifier` field takes an absolute
  filesystem path when `IdentifierType` is `path` (it has no
  `$HOME`/variable expansion), set a **fixed system-wide install
  directory** (under the loader's Advanced Configuration) so one profile
  applies to every user on the device — for example
  `/usr/local/stepsecurity`, which installs the binary at
  `/usr/local/stepsecurity/bin/stepsecurity-dev-machine-guard`.

  Two things that do **not** work as substitutes, so nobody spends an
  afternoon on them:

  - **A symlink at a stable path.** TCC matches the resolved executable,
    not the path used to launch it, so a symlink pointing into `$HOME`
    is evaluated as the `$HOME` path and the profile never matches.
  - **`IdentifierType=bundleID`.** That form is for app bundles. The
    agent is a bare Mach-O CLI binary, so `path` is the only usable
    identifier type.

  See [Migrating a per-user fleet to a fixed install
  path](#migrating-a-per-user-fleet-to-a-fixed-install-path) if the
  fleet is already deployed.

- **The code requirement string** derived from the binary's signature.
  PPPC pairs the install path with this requirement so an impostor
  binary at the same path can't claim the grant. Generate it with:

  ```bash
  codesign -d -r- /path/to/stepsecurity-dev-machine-guard 2>&1 | sed -n 's/^designated => //p'
  ```

  You'll get a line like:

  ```
  identifier "stepsecurity-dev-machine-guard" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "D63S9HLM4L"
  ```

#### PPPC profile XML

Most MDMs (Jamf Pro, Kandji, Intune for macOS, JumpCloud, Mosyle,
SimpleMDM, …) accept a `.mobileconfig` profile or a JSON equivalent
they convert. The relevant payload type is
`com.apple.TCC.configuration-profile-policy`. A profile granting
**SystemPolicyAllFiles** (Full Disk Access) and **SystemPolicyNetworkVolumes**
(container mounts, network shares) to the agent — the same content as
[`packaging/macos/stepsecurity-dev-machine-guard-tcc.mobileconfig`](../packaging/macos/stepsecurity-dev-machine-guard-tcc.mobileconfig),
reproduced here so the payload shape is visible in context:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>io.stepsecurity.dmg.tcc</string>
    <key>PayloadUUID</key>
    <string>REPLACE-WITH-UUIDGEN-OUTPUT</string>
    <key>PayloadDisplayName</key>
    <string>StepSecurity Dev Machine Guard — Full Disk Access</string>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.TCC.configuration-profile-policy</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>io.stepsecurity.dmg.tcc.pppc</string>
            <key>PayloadUUID</key>
            <string>REPLACE-WITH-UUIDGEN-OUTPUT</string>
            <key>Services</key>
            <dict>
                <key>SystemPolicyAllFiles</key>
                <array>
                    <dict>
                        <key>Identifier</key>
                        <string>REPLACE_INSTALL_DIR/bin/stepsecurity-dev-machine-guard</string>
                        <key>IdentifierType</key>
                        <string>path</string>
                        <key>CodeRequirement</key>
                        <string>anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "D63S9HLM4L"</string>
                        <key>Allowed</key>
                        <true/>
                        <key>Comment</key>
                        <string>Allow Dev Machine Guard to scan all files for dev-tool inventory and supply-chain checks.</string>
                    </dict>
                </array>
                <key>SystemPolicyNetworkVolumes</key>
                <array>
                    <dict>
                        <key>Identifier</key>
                        <string>REPLACE_INSTALL_DIR/bin/stepsecurity-dev-machine-guard</string>
                        <key>IdentifierType</key>
                        <string>path</string>
                        <key>CodeRequirement</key>
                        <string>anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "D63S9HLM4L"</string>
                        <key>Allowed</key>
                        <true/>
                        <key>Comment</key>
                        <string>Pre-approve the network-volume prompt so container-runtime mounts (OrbStack, Docker Desktop, Colima virtiofs) are inventoried without asking the developer. Set Allowed to false to pre-deny instead: still no prompt, but no container inventory.</string>
                    </dict>
                </array>
            </dict>
        </dict>
    </array>
</dict>
</plist>
```

Replace:
- Both `REPLACE-WITH-UUIDGEN-OUTPUT` values with fresh UUIDs
  (`uuidgen` on macOS).
- `REPLACE_INSTALL_DIR` with the fixed system-wide install directory you
  configured (for example `/usr/local/stepsecurity`), so the `Identifier`
  resolves to `<install-dir>/bin/stepsecurity-dev-machine-guard`.

The `CodeRequirement` is already pinned to StepSecurity's Apple Developer
Team ID (`D63S9HLM4L`) — leave it as-is.

### Network Volumes pre-approval (recommended for fleets)

The `SystemPolicyNetworkVolumes` block above is what pre-answers the
"would like to access files on a network volume" prompt. Three
outcomes, chosen by the admin rather than by each developer:

| Configuration | Prompt | Container inventory |
|---|---|---|
| `Allowed=true` in PPPC | none | **yes** — full coverage |
| `Allowed=false` in PPPC | none | no (walk gets `EPERM`) |
| No profile, `include_network_volumes: false` | none | no (walk never starts) |
| No profile, default config | **once per user** | yes, if the user clicks Allow |

`Allowed=true` is the one to aim for. `Allowed=false` and
`include_network_volumes: false` reach the same end state by different
routes: the PPPC deny is enforced by macOS and needs the fixed install
path, while the config toggle is enforced by the agent and works on a
per-user install today. Prefer the config toggle if you're not
migrating the install path — it also skips the wasted walk.

#### Migrating a per-user fleet to a fixed install path

PPPC needs one absolute path that applies to every user on the device,
which `~/.stepsecurity/bin/` cannot provide. To move an existing
per-user deployment:

1. **Set the install directory in the loader.** In the StepSecurity
   dashboard's loader Advanced Configuration, set the install dir to a
   system-wide path — `/usr/local/stepsecurity` is the convention. The
   loader places the binary at
   `/usr/local/stepsecurity/bin/stepsecurity-dev-machine-guard` and
   writes `install_dir` into `config.json`; scheduler-fired runs pick it
   up on the next tick with no re-install (resolution order:
   `--install-dir` flag > `install_dir` config > `STEPSECURITY_HOME` env
   > `~/.stepsecurity`).
2. **Re-deploy the loader via MDM.** The next periodic tick installs the
   binary at the new path and rewrites the launchd job to point at it.
3. **Push the PPPC profile** with `REPLACE_INSTALL_DIR` set to the same
   directory.
4. **Verify the path actually took**, since a stale env var or a
   hand-edited config can leave the old location live:

   ```bash
   ps -Ao args | grep -m1 stepsecurity-dev-machine-guard   # what launchd runs
   grep install_dir ~/.stepsecurity/config.json            # what config says
   ```

   Both must show the fixed directory. `config.json` itself stays at
   `~/.stepsecurity/config.json` by design — it is the bootstrap file
   and does not move.
5. **Clean up the old per-user binaries** at
   `~/.stepsecurity/bin/` once the fleet has checked in. Leaving them is
   harmless (nothing launches them), but they'd hold a stale manual FDA
   grant.

Until a device completes this migration, the PPPC profile simply
doesn't match it — the profile is inert, not harmful, and the device
keeps prompting (or keeps honoring `include_network_volumes: false`).
Mixed fleets are fine.

#### Push the profile

| MDM | Path |
|---|---|
| **Jamf Pro** | Computers → Configuration Profiles → New → Upload → select the `.mobileconfig` file. Scope to a Smart Group containing developer machines. |
| **Kandji** | Library → Add new → Custom Profile → upload `.mobileconfig`. Assign the Blueprint that targets developer devices. |
| **Intune (Microsoft)** | Devices → Configuration → Create → macOS → Templates → Custom → upload the `.mobileconfig`. Assign to a device group. |
| **Mosyle** | Management → Profiles → Add → Custom → upload `.mobileconfig`. |
| **JumpCloud** | MDM → Policies → Custom Mac Profile → upload. |

The profile takes effect on the next MDM check-in (usually within
minutes). Verify with:

```bash
# On a managed Mac:
profiles list -all | grep -i stepsecurity
# Or open System Settings → Privacy & Security → Full Disk Access
# and confirm "stepsecurity-dev-machine-guard" is listed and toggled on.
```

Network Volumes has no System Settings pane of its own, so verify that
grant behaviorally instead — on a machine with containers running, a
scan should complete without a prompt and report packages found under
the container mount:

```bash
/usr/local/stepsecurity/bin/stepsecurity-dev-machine-guard \
  --pretty --enable-npm-scan --verbose 2>&1 | grep -i "network volume"
```

Silence means the walk proceeded. A "skipping N network volume(s)" line
means the agent self-censored (`include_network_volumes: false`), which
is the config toggle, not the profile.

### Option B — Manual grant per machine

For dev-only or single-machine testing, grant FDA manually:

1. System Settings → Privacy & Security → Full Disk Access.
2. Click `+`, navigate to
   `~/.stepsecurity/bin/stepsecurity-dev-machine-guard` (use
   <kbd>Cmd</kbd>+<kbd>Shift</kbd>+<kbd>.</kbd> in the file picker to
   show the `.stepsecurity` dotfolder).
3. Toggle the entry on.

The grant is tied to the binary's code signature. If you upgrade the
binary (the loader's auto-update runs on every periodic tick) the
existing grant carries over as long as the signing identity is
unchanged — Dev Machine Guard releases are signed by the same Apple
Developer Team for the life of each major version, so manual grants
survive upgrades within that line.

## Putting it together — the full rollout

A fleet rollout that scans TCC paths typically looks like:

1. Customer's MDM deploys the loader script (downloaded from the
   StepSecurity dashboard for that customer), configured with a fixed
   system-wide install directory.
2. Customer's MDM **also** deploys the PPPC profile (Option A above)
   granting the agent Full Disk Access **and** Network Volumes access.
3. The loader's generated `config.json` includes
   `"include_tcc_protected": true`. Either:
   - Customer edits the loader script's `write_config()` heredoc to
     emit the field before deploying via MDM, **or**
   - Customer pushes a config file alongside the loader (drop into
     `~/.stepsecurity/config.json` via the MDM's file-deploy
     mechanism).

After the next periodic fire, the agent runs with full coverage and no
popups.

A fleet that **can't** move off the per-user install path runs the same
sequence without steps 1–2 and adds `"include_network_volumes": false`
to the config in step 3. No popups either — the trade is the package
inventory inside dev containers.

## What if I see a popup anyway?

If a popup appears after deploying the PPPC profile and setting
`include_tcc_protected: true`, the typical causes:

- **Code requirement mismatch.** The PPPC profile's `CodeRequirement`
  string must match the binary's actual signing. Re-run `codesign -d
  -r-` against the deployed binary and update the profile.
- **Binary path mismatch.** If `IdentifierType=path` is used, the
  `Identifier` must match the absolute path of the binary on disk. Set a
  fixed system-wide install directory so a single path applies to every
  device.
- **TCC.db cache.** TCC caches decisions; after changing a profile,
  reset the relevant service:

  ```bash
  sudo tccutil reset SystemPolicyAllFiles
  sudo tccutil reset SystemPolicyNetworkVolumes   # the container-mount prompt
  ```

  This forces re-evaluation against the latest profile on the next
  access. The agent does not call `tccutil` on its own; this is a
  diagnostic step only.
- **`include_tcc_protected` not actually set.** Verify with
  `cat ~/.stepsecurity/config.json` and re-run the loader's
  `write_config` step if the field is missing.
- **The popup names a network volume.** That's the separate
  `SystemPolicyNetworkVolumes` service — a Full Disk Access grant does
  not cover it. Add the second service block to the profile, or set
  `include_network_volumes: false` if the fleet can't take the profile
  route.
- **A new container runtime appeared.** The mount list is read from the
  kernel at each run, not hard-coded, so a newly installed runtime is
  picked up automatically — including its first prompt. The PPPC grant
  is per-binary, not per-volume, so an existing profile already covers
  it.

## Related

- `internal/tcc/tcc.go` — the skip-list source of truth in this repo;
  `internal/tcc/tcc_darwin.go` holds the protected-path table and the
  `getfsstat`-based network-volume enumeration.
- [`packaging/macos/`](../packaging/macos/) — the ready-made PPPC
  profile covering both services.
- The StepSecurity macOS loader script (the `.sh` your dashboard
  generates for your customer ID) — writes `config.json` on each
  periodic tick, so the `include_tcc_protected` flag travels with the
  loader rollout. Source for this loader lives in the StepSecurity
  agent-api backend, not in this repository.
- [Apple developer docs on PPPC payload](https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol)
  — the full schema for the `com.apple.TCC.configuration-profile-policy` payload.
