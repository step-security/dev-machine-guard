package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/firewall"
	"github.com/step-security/dev-machine-guard/internal/launcher"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/selfupdate"
	"github.com/step-security/dev-machine-guard/internal/telemetry"
	"github.com/step-security/dev-machine-guard/internal/updatestate"
	"github.com/step-security/dev-machine-guard/internal/winproc"
)

// firewallMinBudget is how much of the bootstrap's update deadline must be
// left for the on-device firewall step to start; it then gets
// firewall.ReconcileTimeout. A step the bootstrap killed would count as an
// updater failure, so a long agent update skips it until the next tick.
const firewallMinBudget = 8 * time.Minute

// firewallStepAllowed reports whether the firewall step may run on this tick:
// as SYSTEM, with at least firewallMinBudget of the update deadline left.
func firewallStepAllowed(system bool, elapsed time.Duration) (bool, string) {
	if !system {
		return false, "not running as SYSTEM"
	}
	if left := launcher.DefaultUpdateDeadline - elapsed; left < firewallMinBudget {
		return false, "only " + left.Round(time.Second).String() + " of the update deadline left"
	}
	return true, ""
}

// runFirewallStep is the on-device firewall step of the SYSTEM update tick
// (MSI layout only: runSelfUpdate resolved it). It runs after the agent's own
// update, so a firewall problem never holds up agent updates, and it never
// changes the tick's exit code (the bootstrap counts that code toward the
// updater's failures). start is when this process began.
func runFirewallStep(start time.Time, layout updatestate.Layout, selfExe string, hc *http.Client, deviceID func() string, logf func(string, ...any)) {
	if ok, why := firewallStepAllowed(winproc.IsLocalSystem(), time.Since(start)); !ok {
		logf("firewall: skipping the on-device firewall on this tick: %s", why)
		return
	}
	m := newFirewallManager(layout, selfExe, hc, deviceID, logf)
	if _, err := os.Stat(m.ConfigPath); err != nil {
		logf("firewall: skipping the on-device firewall: no machine config at %s", m.ConfigPath)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), firewall.ReconcileTimeout)
	defer cancel()
	if out := m.Reconcile(ctx); out != firewall.OutcomeNothing {
		logf("firewall: on-device firewall step: %s", out)
	}
}

// newFirewallManager wires firewall.Manager for an MSI layout: the machine
// config the SYSTEM tick read, the layout's protected state\ for staging and
// the report state, and the updater's proxy-aware client.
func newFirewallManager(layout updatestate.Layout, selfExe string, hc *http.Client, deviceID func() string, logf func(string, ...any)) *firewall.Manager {
	return &firewall.Manager{
		APIEndpoint: config.APIEndpoint, CustomerID: config.CustomerID, APIKey: config.APIKey,
		AgentVersion: buildinfo.Version, HTTP: hc, DeviceID: deviceID, Arch: selfupdate.NativeArch(),
		LagBehind: config.UpdateLagBehind, CooldownHours: config.UpdateCooldownHours,
		WantInstall: config.InstallOnDeviceFirewall != nil && *config.InstallOnDeviceFirewall,
		ConfigPath:  filepath.Join(layout.DataRoot, "config.json"),
		StateDir:    layout.StateDir(),
		SelfExe:     selfExe,
		Sys:         firewall.NewSystem(executor.NewReal()),
		Report: func(ctx context.Context, msg string) error {
			return telemetry.PostRunStatusFailed(ctx, hc, deviceID(), msg, firewall.InvocationMethod)
		},
		Logf: logf,
	}
}

// removeFirewallOnUninstall removes the on-device firewall in `uninstall`
// when this agent runs from an MSI layout (the MSI's uninstall action runs
// the seed agent): on MSI hosts the agent owns the firewall, and the firewall
// reads the config.json the uninstall leaves without an agent to manage it.
// On a loader install the loader removes it. Residue is logged and reported
// (on_device_firewall_uninstall_failed); it never fails the uninstall.
func removeFirewallOnUninstall(exec executor.Executor, log *progress.Logger) {
	selfExe, err := os.Executable()
	if err != nil {
		return
	}
	layout, err := updatestate.ResolveLayout(selfExe)
	if err != nil {
		log.Debug("not an MSI layout (%v); the on-device firewall is left to the loader", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), firewall.UninstallTimeout)
	defer cancel()
	deviceID := sync.OnceValue(func() string {
		if winproc.IsLocalSystem() {
			return device.SystemID(ctx, exec, filepath.Join(layout.StateDir(), "device-id"), device.SystemProbeTimeout)
		}
		return resolveDeviceID(ctx)
	})
	m := newFirewallManager(layout, selfExe, selfupdate.NewHTTPClient(), deviceID, func(format string, args ...any) {
		log.Progress(format, args...)
	})
	if left := m.Uninstall(ctx); len(left) > 0 {
		log.Warn("the on-device firewall was not fully removed; still present: %s", strings.Join(left, ", "))
	}
}
