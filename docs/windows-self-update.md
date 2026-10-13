# Windows self-update and recovery

Self-managed script installations opt in with `auto_update: true`. Version-pinned and MSI installations retain their existing update mechanisms. The matching agent-api loader is required; existing deployments need that loader rerun to install the bootstrap and change their scheduled task. Merely upgrading an executable does not migrate the task.

## Scheduled execution

Task Scheduler starts `stepsecurity-dev-machine-guard-bootstrap.exe --recover-update send-telemetry`. The bootstrap is a stable copy of the signed GUI task launcher, installed once after the loader verifies its download. It obtains the installation lock, recovers any pending update, and starts the replaceable `stepsecurity-dev-machine-guard-task.exe`, which starts the agent without a console window. The bootstrap is deliberately outside the self-update transaction. Updates to the bootstrap itself require a deployment maintenance procedure.

The agent checks the backend's existing `latest-binary` endpoint before run gating. The endpoint selects the version using tenant policy and any persisted lag/cooldown overrides. An enterprise manual `send-telemetry` invocation using an opted-in configuration also checks for updates. `STEPSEC_DISABLE_SELF_UPDATE=1` disables this check; it does not disable bootstrap recovery of an already interrupted transaction.

## Verification and replacement

1. Obtain the kernel-owned `.selfupdate.lock`, shared with the loader and launchers. A second updater skips the attempt; launchers wait up to 150 seconds. Process termination releases the lock without stale-lock deletion.
2. Reject malformed versions or versions below 1.18.0, the planned first capable release. The published 1.17.0 does not contain self-update. Keep this floor aligned with the actual release and agent-api template gate if release numbering changes.
3. Require and verify both Ed25519 SSHSIG checksum signatures. Stage changed artifacts from GitHub, with the configured HTTPS packages mirror as a fallback for download failures. Mirror content undergoes the same checksum verification; API credentials are not attached to downloads.
4. Verify every staged hash before modifying either installed file. Updates have a two-minute network/staging budget, with 30-second metadata and 45-second individual download timeouts. Metadata is limited to 64 KiB and each executable to 128 MiB.
5. Save and flush independent backups of both installed executables, then write and flush the rollback journal. Move mapped executables aside and install the staged pair. Remove the journal to commit. The current scan continues on its already loaded image; subsequent runs use the installed pair.

## Failure behavior

| Failure | Result |
| --- | --- |
| Metadata, signature, download or hash failure | Installed pair remains unchanged; the current scan continues and a later invocation retries. |
| Lock contention | No competing installation writes. Updater skips; launcher waits within its bounded timeout. |
| Access denied, sharing violation or second-file installation failure | Attempt to restore both prior files. If restoration is blocked, preserve the journal for recovery on a later launch. |
| Process death between filesystem replacement steps | Stable bootstrap restores the previous pair before launching the agent. This works even when either canonical executable path is missing. |
| Missing, corrupt or unreadable recovery backup/journal | Fail closed: do not launch an uncertain pair. Deployment repair is required. |
| Signed release starts but has a functional defect | No automatic health-based rollback. Use backend version policy to select another capable release, or repair through deployment management. |

Recovery validates both backup hashes before restoring either file, and preserves untouched backup copies until the journal is removed. Mapped retired images may remain until a later launch can delete them. Recovery is tested for process termination; abrupt power loss, filesystem corruption, antivirus products and deployment-specific permissions still need representative device validation. The install directory must remain writable only by its intended account/administrators.

## Validation and rollout

Native Windows x64 and ARM64 CI covers staged-pair validation, live executable replacement, subprocess termination at each replacement boundary, kernel lock release, bootstrap recovery with missing executables, PowerShell/Go lock interoperability, and sharing violations. agent-api tests cover template selection and Windows PowerShell installer functions in temporary directories.

Release the capable signed agent before exposing direct scheduling to customers. Deploy the matching loader to a disposable device, verify the registered task and custom configuration path, then exercise update and recovery under the customer's account, proxy and endpoint protection configuration. Expand from a canary group after confirming scheduled scans and reported versions. Required PR review and repository checks remain merge prerequisites.
