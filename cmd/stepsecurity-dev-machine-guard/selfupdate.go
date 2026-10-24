package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/step-security/dev-machine-guard/internal/authenticode"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/faultinject"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/selfupdate"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
	"github.com/step-security/dev-machine-guard/internal/winproc"
)

const (
	installChannelMSI   = "msi"
	deviceProbeTimeout  = 30 * time.Second
	updateLogMaxBytes   = 1 << 20
	selfCheckExitFailed = 1
)

// runEarlyVerbs handles the verbs that must not go through the scan CLI:
// the agent.prestart fault checkpoint (spec Contracts, harness H0) and the
// self-update verbs, which exit here.
func runEarlyVerbs(args []string) {
	if err := faultinject.Point("agent.prestart"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(3)
	}
	if len(args) == 0 {
		return
	}
	switch args[0] {
	case "self-update":
		os.Exit(runSelfUpdate(args[1:]))
	case "self-check":
		os.Exit(runSelfCheck())
	}
}

// resolveDeviceID is the scan's device id (user context), for events the
// scanning agent sends. SYSTEM paths use device.SystemID instead.
func resolveDeviceID(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, deviceProbeTimeout)
	defer cancel()
	return device.ID(model.Device{SerialNumber: device.SerialNumber(ctx, executor.NewReal())})
}

// selfCheckDeviceID resolves the self-check's device id. As SYSTEM (the
// updater's S5 smoke) it goes through device.SystemID like every other
// SYSTEM resolution in self-update, so it never writes the shared
// device-id file from a fallback; elsewhere it is the scan's resolution.
func selfCheckDeviceID(ctx context.Context, exec executor.Executor, system bool, cachePath string) string {
	if system {
		// Short probe: the smoke test's limit must exceed this (asserted
		// in selfupdate); a wedged WMI falls through to the SYSTEM cache.
		return device.SystemID(ctx, exec, cachePath, selfupdate.SelfCheckProbeTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, deviceProbeTimeout)
	defer cancel()
	return device.ID(model.Device{SerialNumber: device.SerialNumber(ctx, exec)})
}

// runSelfCheck is `agent self-check`: the S5 smoke test run by the updater
// against a staged version. It always exits 0 once it can print.
func runSelfCheck() int {
	config.Load()
	sc := selfupdate.SelfCheck{
		Version:  buildinfo.Version,
		ConfigOK: config.LoadError() == nil && config.IsEnterpriseMode(),
	}
	system := runtime.GOOS == model.PlatformWindows && winproc.IsLocalSystem()
	cachePath := ""
	if system {
		if l, err := ownLayout(); err == nil {
			cachePath = filepath.Join(l.StateDir(), "device-id")
		}
	}
	sc.DeviceID = selfCheckDeviceID(context.Background(), executor.NewReal(), system, cachePath)
	if err := json.NewEncoder(os.Stdout).Encode(sc); err != nil {
		return selfCheckExitFailed
	}
	return 0
}

// runSelfUpdate is `agent self-update --system`, run by the SYSTEM update
// task through the bootstrap.
func runSelfUpdate(args []string) int {
	if len(args) != 1 || args[0] != "--system" {
		fmt.Fprintln(os.Stderr, "usage: self-update --system")
		return 2
	}
	if runtime.GOOS != model.PlatformWindows {
		fmt.Fprintln(os.Stderr, "self-update --system is only supported on Windows MSI installs")
		return 2
	}
	selfExe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "self-update: own path: %v\n", err)
		return selfupdate.ExitFailed
	}
	// The root comes from our own path (any INSTALLFOLDER), by the
	// bootstrap's rule; an untrusted root is refused, never guessed.
	layout, err := updatestate.ResolveLayout(selfExe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "self-update: %s: %v\n", selfupdate.EventStateCorrupt, err)
		return selfupdate.ExitFailed
	}
	logf := newUpdateLog(layout.LogFile())

	config.Load()
	if err := config.LoadError(); err != nil {
		logf("self-update: config: %v", err)
	}
	if !config.IsEnterpriseMode() {
		logf("self-update: no enterprise configuration; nothing to do")
		return selfupdate.ExitFailed
	}
	self, err := updatestate.ParseVersion(buildinfo.Version)
	if err != nil {
		logf("self-update: own version %q is not x.y.z", buildinfo.Version)
		return selfupdate.ExitFailed
	}
	httpClient := selfupdate.NewHTTPClient()
	// The SYSTEM chain never reads the user-writable device-id file.
	deviceID := sync.OnceValue(func() string {
		return device.SystemID(context.Background(), executor.NewReal(), filepath.Join(layout.StateDir(), "device-id"), device.SystemProbeTimeout)
	})
	exec := executor.NewReal()
	machineConfig := config.ConfigFilePath()

	deps := &selfupdate.Deps{
		Layout:  layout,
		Self:    self,
		SelfExe: selfExe,
		Client: &selfupdate.Client{
			HTTP: httpClient, APIEndpoint: config.APIEndpoint, CustomerID: config.CustomerID,
			APIKey: config.APIKey, AgentVersion: buildinfo.Version, Arch: selfupdate.NativeArch(),
			LagBehind: config.UpdateLagBehind, CooldownHours: config.UpdateCooldownHours,
			MirrorURL: config.UpdateMirrorURL,
		},
		AutoUpdate:      config.AutoUpdate == nil || *config.AutoUpdate,
		VerifyPublisher: func(p string) error { return authenticode.SamePublisher(p, selfExe) },
		VerifySeed:      func(p string) error { return authenticode.SameSeedPublisher(p, selfExe) },
		InstallerBusy:   selfupdate.InstallerBusy,
		Smoke:           selfupdate.RunSmoke,
		AcquireInstance: func() (func(), error) {
			lk, err := lock.Acquire(exec)
			if err != nil {
				return nil, err
			}
			return lk.Release, nil
		},
		EnsureACLs: func() ([]string, error) {
			var drifted []string
			var errs []error
			for _, d := range []string{layout.VersionsDir(), layout.StateDir()} {
				fixed, err := updatestate.EnsureProtectedDir(d)
				if fixed {
					drifted = append(drifted, d)
				}
				errs = append(errs, err)
			}
			fixed, err := selfupdate.EnsureConfigACL(machineConfig)
			if fixed {
				drifted = append(drifted, machineConfig)
			}
			errs = append(errs, err)
			return drifted, errors.Join(errs...)
		},
		RefreshDeviceID: func(context.Context) { _ = deviceID() },
		Send: func(ctx context.Context, ev updatestate.OutboxEvent) error {
			err := telemetry.PostUpdateEvent(ctx, httpClient, telemetry.UpdateEvent{
				ExecutionID: ev.ExecutionID, DeviceID: deviceID(), InstallChannel: installChannelMSI,
				Event: ev.Event, From: ev.From, To: ev.To, Error: ev.Error,
			})
			if errors.Is(err, telemetry.ErrUpdateEventRejected) {
				return fmt.Errorf("%w: %w", selfupdate.ErrEventRejected, err)
			}
			return err
		},
		SetRunningVersion: func(v string) {
			if err := selfupdate.SetRunningVersion(v); err != nil {
				logf("self-update: RunningVersion: %v", err)
			}
		},
		FreeBytes: selfupdate.FreeBytes,
		Now:       time.Now,
		Logf:      logf,
	}
	return selfupdate.Run(context.Background(), deps)
}

// newUpdateLog appends timestamped lines to state\update.log (kept under
// 1 MiB, one rotated copy) and stderr.
func newUpdateLog(path string) func(string, ...any) {
	var mu sync.Mutex
	return func(format string, args ...any) {
		line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
		mu.Lock()
		defer mu.Unlock()
		_, _ = io.WriteString(os.Stderr, line)
		if fi, err := os.Stat(path); err == nil && fi.Size() > updateLogMaxBytes {
			_ = os.Rename(path, path+".1")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- state\ ACL is set by the updater
			return
		}
		// #nosec G302 G304 -- fixed path inside the protected state directory.
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
}

// parseBootstrapFallback reads STEPSEC_BOOTSTRAP_FALLBACK=<reason>[:<version>]
// as dmg-boot writes it: the reason is the part before the first ':', and
// the suffix names the version that was missing or failed to start. Spec
// §7: update_from = the version state.json named (the suffix, else named,
// state.json's current); update_to = the version actually run (ran, from
// STEPSEC_BOOTSTRAP_VERSION, else self).
func parseBootstrapFallback(env, named, ran, self string) (reason, from, to string) {
	reason, suffix, _ := strings.Cut(env, ":")
	from = named
	if v, _, _ := strings.Cut(suffix, ":"); v != "" {
		if pv, err := updatestate.ParseVersion(v); err == nil {
			from = pv.String()
		}
	}
	to = self
	if pv, err := updatestate.ParseVersion(ran); err == nil {
		to = pv.String()
	}
	return reason, from, to
}

// reportBootstrapFallback sends update_pointer_invalid when the bootstrap
// ran a fallback version (STEPSEC_BOOTSTRAP_FALLBACK=<reason>[:<version>]).
// Best-effort; the bootstrap sets it on every fallback run until the
// updater repairs the pointer.
func reportBootstrapFallback() {
	env := os.Getenv(telemetry.EnvBootstrapFallback)
	if env == "" || runtime.GOOS != model.PlatformWindows {
		return
	}
	named := ""
	if l, err := ownLayout(); err == nil {
		if st, _, err := updatestate.Load(l.StateFile()); err == nil && st != nil {
			named = st.Current
		}
	}
	reason, from, to := parseBootstrapFallback(env, named, os.Getenv(telemetry.EnvBootstrapVersion), buildinfo.Version)
	ctx, cancel := context.WithTimeout(context.Background(), deviceProbeTimeout)
	defer cancel()
	err := telemetry.PostUpdateEvent(ctx, nil, telemetry.UpdateEvent{
		ExecutionID: uuid.NewString(), DeviceID: resolveDeviceID(ctx), InstallChannel: installChannelMSI,
		Event: selfupdate.EventPointerInvalid, From: from, To: to, Error: reason,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] update_pointer_invalid not sent: %v\n", err)
	}
}

// ownLayout is the MSI layout of this binary (updatestate.ResolveLayout).
func ownLayout() (updatestate.Layout, error) {
	exe, err := os.Executable()
	if err != nil {
		return updatestate.Layout{}, err
	}
	return updatestate.ResolveLayout(exe)
}
