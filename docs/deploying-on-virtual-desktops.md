# Virtual desktop deployment

The agent uses one internal device identity per host. The resolver in #243
keeps root and user scans on the same registration and rejects placeholder
serials. WSL distributions continue using separate host/distro-derived IDs.

Administrators assign a display device ID through the StepSecurity console or
its managed-ID API. The backend enforces uniqueness, audit history, and the
three-change limit. Changing a display ID does not change agent registration,
scan caches, or policies.

Local `device_id` configuration, `STEPSEC_DEVICE_ID`, MSI `DEVICEID`, and
`configure --device-id` do not configure registration identity. Legacy JSON
keys and environment variables are ignored; the CLI flag is rejected. Do not
use hostname or username templates to carry identity between rebuilt hosts.
A rebuilt machine whose internal identity changes is a new registration.
Do not copy identity/cache files into golden images.

This revision does not support separate registration per user on shared hosts.
Per-user enrollment requires a centrally controlled design and is deferred.
Normal host-level scan state, locking and scheduler behavior remain in place.

## Retirement on teardown

Retirement requires the backend retirement endpoints in agent-api#11404 (release) / #11412 (integration).
The default is off. Administrators can enable it in the bootstrap config:

```json
{
  "customer_id": "example-org",
  "api_endpoint": "https://api.example.com",
  "api_key": "<telemetry-key>",
  "retire_on_uninstall": true
}
```

For MSI deployment, use `RETIREONUNINSTALL=1`. For scripted provisioning:

```sh
stepsecurity-dev-machine-guard configure --retire-on-uninstall=true
```

`uninstall --retire` retires the resolved internal host identity before removing
the scheduled task. `uninstall --no-retire` suppresses the request, including on
MSI major upgrades. Cached identities in `last-run.json` or user state directories
cannot select additional devices to retire. Display IDs are never retirement keys.

The request is best effort, with a ten-second total budget and one retry for
transport/server failures. Offline or unsupported backends produce a warning
and do not block uninstall. If the host disappears without an uninstall, use
the backend's inactivity retirement policy. Retirement does not clear the
managed-ID history or reset the three-change allowance for the same identity.

Windows SYSTEM, service accounts, and machine accounts are reported as
`no_user_logged_in` instead of being attributed to a developer. Telemetry
reports `device_id_source` as `serial` or `wsl_guest`.

The companion installer presets and loader identity overrides in those backend
PRs and console#4506 must also be reconciled before a combined VDI rollout.
Do not deploy their hostname/user/custom identity presets with this agent.
