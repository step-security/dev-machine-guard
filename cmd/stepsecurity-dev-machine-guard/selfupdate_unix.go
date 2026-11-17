//go:build !windows

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/paths"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/selfupdate"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
)

// installChannelLoader is the install_channel of macOS/Linux update events:
// the loader installed the binary and the scheduler runs it directly.
const installChannelLoader = "loader"

// scheduledSelfUpdate runs one macOS/Linux self-update tick ahead of a
// send-telemetry run. Only binary-scheduled installs take part: the loader
// writes auto_update: true when it registers launchd/systemd to run the
// binary directly (nothing re-runs the loader afterwards), while pinned
// installs and script-scheduled installs, whose loader converges the binary
// on every tick, never carry the key. STEPSEC_DISABLE_SELF_UPDATE=1 turns it
// off on a device. Best-effort by contract: the tick never fails the run.
func scheduledSelfUpdate(exec executor.Executor, log *progress.Logger) {
	if config.AutoUpdate == nil || !*config.AutoUpdate {
		return
	}
	if exec.Getenv(selfupdate.EnvDisable) == "1" {
		log.Debug("self-update: disabled by %s", selfupdate.EnvDisable)
		return
	}
	self, err := updatestate.ParseVersion(buildinfo.Version)
	if err != nil {
		log.Debug("self-update: own version %q is not x.y.z; skipped", buildinfo.Version)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		log.Warn("self-update: own path: %v", err)
		return
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != "" {
		exe = resolved
	}
	// Two instances (a manual run beside the scheduled one) must not stage
	// over each other; the loser simply skips its tick.
	held, err := lock.AcquireSibling("self-update")
	if err != nil {
		if !errors.Is(err, lock.ErrHeld) {
			log.Debug("self-update: lock: %v", err)
		}
		return
	}
	defer held.Release()

	httpClient := selfupdate.NewHTTPClient()
	deviceID := sync.OnceValue(func() string { return resolveDeviceID(context.Background()) })
	deps := &selfupdate.UnixDeps{
		Self:     self,
		SelfExe:  exe,
		GOOS:     runtime.GOOS,
		StateDir: paths.Home(),
		Client: &selfupdate.Client{
			HTTP: httpClient, APIEndpoint: config.APIEndpoint, CustomerID: config.CustomerID,
			APIKey: config.APIKey, AgentVersion: buildinfo.Version, Arch: selfupdate.NativeArch(),
			LagBehind: config.UpdateLagBehind, CooldownHours: config.UpdateCooldownHours,
			MirrorURL: config.UpdateMirrorURL, DeviceID: deviceID,
		},
		Smoke: selfupdate.RunSmoke,
		Send: func(ctx context.Context, ev updatestate.OutboxEvent) error {
			id := deviceID()
			if id == "" {
				return errors.New("no device identity to attribute the event to")
			}
			return telemetry.PostUpdateEvent(ctx, httpClient, telemetry.UpdateEvent{
				ExecutionID: ev.ExecutionID, DeviceID: id, InstallChannel: installChannelLoader,
				Event: ev.Event, From: ev.From, To: ev.To, Error: ev.Error,
			})
		},
		FreeBytes: selfupdate.FreeBytes,
		Now:       time.Now,
		Log:       log,
	}
	selfupdate.RunUnix(context.Background(), deps)
}
