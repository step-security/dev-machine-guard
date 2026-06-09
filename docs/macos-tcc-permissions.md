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
```

### Persistent config (`~/.stepsecurity/config.json`)

```json
{
  "customer_id": "your-customer-id",
  "api_endpoint": "https://api.stepsecurity.io",
  "api_key": "step_…",
  "scan_frequency_hours": "4",
  "include_tcc_protected": true
}
```

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

Two paths to grant FDA:

### Option A — MDM-pushed PPPC profile (recommended for fleets)

Apple's **Privacy Preferences Policy Control (PPPC)** payload lets MDM
admins pre-approve specific binaries for specific TCC services. The
end user sees nothing; the grant is in place the moment the device
checks in with the MDM.

This is the only way to grant FDA at scale without per-user clicks.

#### Inputs you need

- **The install path of the binary.** The loader installs at
  `~/.stepsecurity/bin/stepsecurity-dev-machine-guard` — that's
  per-user (`/Users/<username>/.stepsecurity/bin/...`). PPPC's
  `Identifier` field always takes an absolute filesystem path when
  `IdentifierType` is `path` (it has no `$HOME`/variable expansion),
  so you either:
  - scope a per-user profile that substitutes each user's home path,
    using your MDM's per-user variables (Jamf's `$HOME`-substituting
    profile payload variables, Kandji's user-context blueprints,
    Intune's per-user assignment, etc.), or
  - have the operator install the binary at a fixed system-wide path
    (for example `/usr/local/bin/stepsecurity-dev-machine-guard`) so
    the same profile applies to every user on the device.

- **The code requirement string** derived from the binary's signature.
  PPPC pairs the install path with this requirement so an impostor
  binary at the same path can't claim the grant. Generate it with:

  ```bash
  codesign -d -r- /path/to/stepsecurity-dev-machine-guard 2>&1 | sed -n 's/^designated => //p'
  ```

  You'll get a line like:

  ```
  identifier "stepsecurity-dev-machine-guard" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "<TEAM_ID>"
  ```

#### PPPC profile XML

Most MDMs (Jamf Pro, Kandji, Intune for macOS, JumpCloud, Mosyle,
SimpleMDM, …) accept a `.mobileconfig` profile or a JSON equivalent
they convert. The relevant payload type is
`com.apple.TCC.configuration-profile-policy`. A minimal profile
granting **SystemPolicyAllFiles** (Full Disk Access) to the agent:

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
                        <string>/Users/REPLACE_USERNAME/.stepsecurity/bin/stepsecurity-dev-machine-guard</string>
                        <key>IdentifierType</key>
                        <string>path</string>
                        <key>CodeRequirement</key>
                        <string>identifier "stepsecurity-dev-machine-guard" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "REPLACE_TEAM_ID"</string>
                        <key>Allowed</key>
                        <true/>
                        <key>Comment</key>
                        <string>Allow Dev Machine Guard to scan all files for dev-tool inventory and supply-chain checks.</string>
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
- `REPLACE_USERNAME` with the target user's short username so the
  `Identifier` resolves to the actual on-disk binary path. For
  per-user MDM scoping, use your MDM's per-user variable instead of a
  literal username (e.g., Jamf's `$USERNAME`, Kandji's user-context
  variable). For a fixed system-wide install, replace the whole
  `Identifier` value with the absolute path you chose
  (e.g., `/usr/local/bin/stepsecurity-dev-machine-guard`).
- `REPLACE_TEAM_ID` with the Apple Developer Team ID embedded in
  the binary's code requirement (the trailing `subject.OU` field
  from the `codesign -d -r-` output above).

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
   StepSecurity dashboard for that customer).
2. Customer's MDM **also** deploys the PPPC profile (Option A above)
   granting the agent Full Disk Access.
3. The loader's generated `config.json` includes
   `"include_tcc_protected": true`. Either:
   - Customer edits the loader script's `write_config()` heredoc to
     emit the field before deploying via MDM, **or**
   - Customer pushes a config file alongside the loader (drop into
     `~/.stepsecurity/config.json` via the MDM's file-deploy
     mechanism).

After the next periodic fire, the agent runs with full coverage and no
popups.

## What if I see a popup anyway?

If a popup appears after deploying the PPPC profile and setting
`include_tcc_protected: true`, the typical causes:

- **Code requirement mismatch.** The PPPC profile's `CodeRequirement`
  string must match the binary's actual signing. Re-run `codesign -d
  -r-` against the deployed binary and update the profile.
- **Binary path mismatch.** If `IdentifierType=path` is used, the
  `Identifier` must match the absolute path of the binary on disk.
  Different per-user install dirs can require deploying the profile
  with a wildcard-friendly identifier (use the code requirement
  alone, with `IdentifierType=bundleID`-style matching, or push the
  profile per user).
- **TCC.db cache.** TCC caches decisions; after changing a profile,
  reset the relevant service:

  ```bash
  sudo tccutil reset SystemPolicyAllFiles
  ```

  This forces re-evaluation against the latest profile on the next
  access. The agent does not call `tccutil` on its own; this is a
  diagnostic step only.
- **`include_tcc_protected` not actually set.** Verify with
  `cat ~/.stepsecurity/config.json` and re-run the loader's
  `write_config` step if the field is missing.

## Related

- `internal/tcc/tcc.go` — the skip-list source of truth in this repo.
- The StepSecurity macOS loader script (the `.sh` your dashboard
  generates for your customer ID) — writes `config.json` on each
  periodic tick, so the `include_tcc_protected` flag travels with the
  loader rollout. Source for this loader lives in the StepSecurity
  agent-api backend, not in this repository.
- [Apple developer docs on PPPC payload](https://developer.apple.com/documentation/devicemanagement/privacypreferencespolicycontrol)
  — the full schema for the `com.apple.TCC.configuration-profile-policy` payload.
