# macOS MDM packaging

This directory holds the configuration-profile artifacts MDM admins push
alongside the agent. There is no installer package here — macOS
deployment goes through the StepSecurity loader script the dashboard
generates per customer.

## `stepsecurity-dev-machine-guard-tcc.mobileconfig`

A PPPC (Privacy Preferences Policy Control) profile that pre-approves
two TCC services for the agent, so developers never see a permission
prompt:

| Service | Covers | Needed when |
|---|---|---|
| `SystemPolicyAllFiles` | Full Disk Access — `~/Documents`, `~/Downloads`, `~/Library`, … | `include_tcc_protected: true` |
| `SystemPolicyNetworkVolumes` | Non-local mounts, including container-runtime filesystems (OrbStack, Docker Desktop, Colima virtiofs) | **the default config** — the agent walks these to inventory packages inside dev containers |

The second one surprises people: the agent walks container mounts out of
the box, and macOS gates that behind its own service which a Full Disk
Access grant does **not** cover.

### Before deploying

1. Replace `REPLACE-WITH-UUIDGEN-OUTPUT-1` and `-2` with fresh UUIDs
   (`uuidgen`).
2. Replace `REPLACE_INSTALL_DIR` with the fixed system-wide install
   directory configured in the loader — `/usr/local/stepsecurity` is the
   convention.

The install path **must** be system-wide. PPPC path identifiers have no
`$HOME` expansion, so the default per-user install at
`~/.stepsecurity/bin/` cannot be targeted by any profile, and a symlink
at a stable path doesn't help (TCC matches the resolved executable).

Leave `CodeRequirement` as-is — it is pinned to StepSecurity's Apple
Developer Team ID (`D63S9HLM4L`).

### Pre-deny instead of pre-approve

Set `Allowed` to `false` on a service to answer the prompt with a denial
rather than a grant. Developers still see nothing; the agent's reads in
that class fail and the rest of the scan completes normally.

For network volumes specifically there's a second way to get the same
end state without a profile — and therefore without the fixed install
path: `"include_network_volumes": false` in `config.json` stops the
agent from walking them at all. That's the route for fleets already
deployed per-user.

### Push it

Upload as a custom profile in your MDM (Jamf Pro, Kandji, Intune,
Mosyle, JumpCloud all accept `.mobileconfig`), scoped to the developer
machines. It takes effect on the next check-in.

Full walkthrough, verification commands, and the migration steps for an
existing per-user fleet:
[`docs/macos-tcc-permissions.md`](../../docs/macos-tcc-permissions.md).
