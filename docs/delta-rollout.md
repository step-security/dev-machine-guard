# Tenant rollout of delta package uploads

Legacy full package reporting is the default. The agent enables delta only when its current run-config response includes:

```json
{"package_scan":{"delta_enabled":true}}
```

A missing, null, malformed, or false setting, an older backend, or a failed check-in selects legacy. The setting is not remembered between invocations. Forced scans still honor it. This changes the upload protocol for npm and Python, not disk-versus-command inventory collection or suspicious-file rules.

Run-config is the only source of truth. The retired `use_legacy_package_scan` config field and `STEPSEC_ENABLE_SCAN_STATE` / `STEPSEC_DISABLE_SCAN_STATE` environment variables are ignored, including telemetry-out runs. Existing config files containing the retired field remain readable.

Before a legacy upload (or telemetry-out dump), the agent removes the old delta baseline. If removal fails, the upload is stopped rather than leaving a stale baseline that could later reference replaced inventory. A subsequent delta run starts fresh and sends full bodies for its scanned inventory; normal scan limits still apply. Failed or rejected delta uploads retain the existing retry behavior.

Deploy backend support first, then the updated agent with legacy as default. Opt selected tenants in through the authenticated tenant configuration API:

```http
PUT /v1/{customer}/developer-mdm/config
Content-Type: application/json

{"package_scan":{"delta_enabled":true}}
```

Send false to roll back. Changes apply at the next check-in, not midway through an active scan. Old agents ignore this field and retain their old defaults; backend rollout alone cannot disable delta on those versions.
