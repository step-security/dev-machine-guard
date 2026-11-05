# Dev Container lifecycle PoC

This opt-in Linux integration keeps container lifecycle separate from scan status.
Install the PoC `stepsecurity-dev-machine-guard` binary on the container's PATH
when building its image. Generate scripts on the host with the same version:

```sh
stepsecurity-dev-machine-guard container scripts --output .devcontainer/dmg
```

Merge the generated `postStartCommand` into your existing devcontainer.json:

```json
{"postStartCommand":"sh .devcontainer/dmg/start.sh"}
```

Provide DMG_CUSTOMER_ID, DMG_API_ENDPOINT and DMG_API_KEY through your runtime
secret mechanism, or configure DMG before starting. Do not commit credentials or
put enrolled state in a reusable image. `container start` creates private state
under the executing user's `~/.stepsecurity/container`, uses a generated device
ID, and starts one worker. `container setup` performs configuration without
starting the worker. `--state-dir DIR` is available for direct commands; generated
scripts use the default. Do not share this directory between container instances.

Stop from the host using the generated wrapper:

```sh
sh .devcontainer/dmg/stop.sh my-container vscode
```

The second argument must be the user that ran postStartCommand (use root only
when startup ran as root). This selects the same private state and control socket.
The wrapper quiesces scanning and heartbeats and reports stopped before stopping
the container. If reporting fails it warns and still stops the container.
Ordinary stop/start reuses the device ID; each restart gets a new lifecycle run.

There is no standard Dev Container stop hook. Closing an editor, directly running
`docker stop`, killing a container, or losing its host can bypass the wrapper.
Heartbeats run every 30 seconds; the backend derives offline after 120 seconds
without a heartbeat. Offline does not prove that the container was destroyed.
No permanent retirement, credential revocation, uninstall, or deletion occurs.

Deploy the API's DeveloperMDMContainerLifecycle table and lifecycle handler before
using these scripts. The PoC uses the existing tenant onboarding credential; it
does not provide per-device authentication. Lifecycle events include an ordered
server generation and sequence so old events cannot reactivate a stopped run.
Normal scan telemetry continues through the existing telemetry endpoint.

## Ownership and workspace

Assigned owner uses the existing DMG user identity. Provision `configure --user-id`
before container setup when the OS account has no usable user identity. Do not
assume this overrides a detected normal OS user.

Inside the container, use the same user for setup and start:

```sh
stepsecurity-dev-machine-guard container setup \
  --workspace-name "widgets" \
  --repository-url "https://github.com/example-org/widgets" \
  --environment devcontainer
stepsecurity-dev-machine-guard container start
```

Metadata is optional and explicitly supplied. Supported environments are `docker`,
`devcontainer`, and `codespaces`; selecting one does not certify runtime support.
Repository URLs must use HTTPS without credentials, query parameters or fragments.
Workspace labels are limited to 128 UTF-8 bytes and must not contain control characters.
Omitted flags preserve configured values; an empty value clears the corresponding
field. Changes take effect on the next lifecycle start and do not alter a running
instance or its device ID. Metadata is stored privately, outside the workspace,
and each new run sends a full snapshot. No local paths or Git secrets are discovered.

The console retains reported start and stop times for the current run. Offline
means missing heartbeats, not a reported stop or confirmed deletion.
