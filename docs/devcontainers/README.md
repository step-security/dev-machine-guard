# Monitor development containers

Use Dev Machine Guard (DMG) to monitor Linux development containers and show their
workspace, owner, and lifecycle status in the StepSecurity console. Container
status is separate from scan results: a running container may still have a
failed or pending scan.

## Before you start

- Install a DMG version that includes the `container` commands in your Linux
  container image. Make `stepsecurity-dev-machine-guard` available on `PATH`.
- Obtain your organization's DMG configuration from the StepSecurity console.
- Use the same container user for setup, startup, and shutdown reporting.
- The shutdown script below requires Docker access on the host.

Provide `DMG_CUSTOMER_ID`, `DMG_API_ENDPOINT`, and `DMG_API_KEY` through your
container runtime's secret configuration, or configure DMG inside the container
before starting it. Do not commit credentials to your project or bake a configured
device identity into a reusable image.

## Start DMG with your container

From your project directory on the host, generate the integration scripts using
the same DMG version installed in the container:

```sh
stepsecurity-dev-machine-guard container scripts --output .devcontainer/dmg
```

Add the generated startup command to `.devcontainer/devcontainer.json`:

```json
{
  "postStartCommand": "sh .devcontainer/dmg/start.sh"
}
```

If you already have a `postStartCommand`, incorporate the DMG command into your
existing startup script rather than replacing the other commands.

The startup script runs **inside the container**. It configures that instance if
needed, starts DMG, and waits for it to become ready. Starting DMG again while it
is already running does not launch a second worker.

To start DMG manually inside a container:

```sh
stepsecurity-dev-machine-guard container start
```

## Add ownership and workspace details

The console uses DMG's existing user identity for ownership. When the container
has no usable user identity, configure an explicit user ID before the first
`container setup` or `container start`:

```sh
stepsecurity-dev-machine-guard configure --user-id developer@example.com
```

This does not override a normal user identity detected from the operating system.

Workspace details are optional. Set them **inside the container**, before startup:

```sh
stepsecurity-dev-machine-guard container setup \
  --workspace-name "widgets" \
  --repository-url "https://github.com/example-org/widgets" \
  --environment devcontainer
stepsecurity-dev-machine-guard container start
```

- `--workspace-name`: a friendly label, up to 128 UTF-8 bytes, without control characters.
- `--repository-url`: an HTTPS URL without credentials, query parameters, or fragments.
- `--environment`: a display label: `docker`, `devcontainer`, or `codespaces`.
  The label does not configure startup or shutdown integration for that environment.

Omitting a flag keeps its configured value; passing an empty value clears it.
Updates appear after the next DMG lifecycle start. Running setup does not interrupt
an active worker. DMG does not automatically discover workspace paths or repository
URLs.

## Stop your container

For an explicit stop report, run the generated wrapper **from the Docker host**:

```sh
sh .devcontainer/dmg/stop.sh example-container vscode
```

Replace `example-container` with the Docker container name and `vscode` with the
user that started DMG inside it. Use `root` only if DMG also started as root.

The wrapper asks DMG to stop scanning and report its stopped state, then stops
the Docker container. If reporting fails, it prints a warning and still stops
the container.

To stop only DMG and leave the container running, execute this inside the container:

```sh
stepsecurity-dev-machine-guard container stop
```

Closing an editor, calling `docker stop` directly, or losing the container's host
can bypass shutdown reporting. In those cases, the console uses missed heartbeats
to show the container as offline.

## Understand the status

| Status | Meaning |
| --- | --- |
| Running | DMG is sending heartbeats, normally every 30 seconds. |
| Stopped | DMG explicitly reported a stop. |
| Offline | No heartbeat has arrived for two minutes. The container may have stopped or become unreachable. |

Offline does not confirm that a container was deleted. Stopping DMG does not
retire the device or delete its history. Start and stop timestamps are shown when
available; a missing heartbeat does not establish a stop time.

## Preserve each container's identity

DMG stores private state in the executing user's `~/.stepsecurity/container`.
Stopping and starting the same container preserves its device ID when this state
is retained. Recreating a container without its state creates a new identity.

Keep state outside the shared project directory. Never share it between container
instances or include enrolled state in a reusable image. Direct commands support
`--state-dir DIR`; the generated scripts use the default directory, so use a
consistent path if you write your own wrappers.
