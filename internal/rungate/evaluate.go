package rungate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// serialProbeTimeout bounds the one-off device-id probe (macOS ioreg is the
// slow case). The result is cached in the state file, so only a device's
// first gated invocation pays it.
const serialProbeTimeout = 10 * time.Second

// Result is what main acts on: skip (exit 0 quietly) or proceed. Detail is a
// preformatted human fragment for the single skip log line.
type Result struct {
	Skip   bool
	Reason string
	Detail string
	// WSL is the tenant's WSL-scanning switch, carried out of the same
	// check-in. Zero (disabled) on every path that does not reach a backend
	// answer — see WSLDirective: this one fails closed.
	WSL WSLDirective
}

// Evaluate runs the whole gate ahead of telemetry.Run: explicit escapes,
// cached-or-probed device id, the backend check-in, the decision, and state
// persistence. It makes one or two network calls — the backend check-in, plus
// a best-effort gated-skip heartbeat on an online skip (and none at all when an
// escape short-circuits) — and NEVER fails the run: every error path degrades
// to Skip=false. Lock contention is deliberately NOT handled here: a not-due
// wakeup skips on the directive before the run ever tries the lock, and a due
// wakeup that collides with a running scan is left to telemetry.Run's
// lock.Acquire so it reports the contention as before.
// guestDeviceID, when non-empty, is the identity of an agent running inside a
// WSL distribution, derived by the host that triggered it. It must be used in
// preference to any local probe: a distro's own serial is its machine-id — or
// "unknown" on a minimal or WSL1 distro — so gating on it would check in
// against the wrong device record, or none.
func Evaluate(ctx context.Context, exec executor.Executor, log *progress.Logger, forceScan bool, guestDeviceID string) Result {
	in := Inputs{
		ForceScan:  forceScan || os.Getenv("STEPSEC_FORCE_SCAN") == "1",
		KillSwitch: os.Getenv("STEPSEC_DISABLE_RUN_GATE") == "1",
		Now:        time.Now(),
	}

	// Local escapes need no I/O at all; resolve them before touching disk or
	// network. Everything else defers to the backend's scan directive — there
	// is no agent-side feature flag, so the feature is turned on or off
	// entirely from the backend.
	if in.ForceScan || in.KillSwitch {
		if in.ForceScan {
			log.Progress("Run gate: bypassed (--force-scan)")
		}
		// Note the asymmetry: bypassing the cadence gate does NOT enable WSL
		// scanning. Without a directive we never scan inside a distro.
		return Result{Skip: false, Reason: Decide(in).Reason, WSL: wslWithOverride(WSLDirective{})}
	}

	// Device id: the guest identity when we were given one, else cached from a
	// prior run, else a bounded local probe. Without a real id the backend
	// can't be asked anything meaningful — fail open rather than gate on a
	// bogus one.
	st, stOK := readState()
	deviceID := strings.TrimSpace(guestDeviceID)
	if deviceID != "" {
		log.Debug("run-gate: gating as WSL guest %s", deviceID)
	} else {
		deviceID = st.DeviceID
		if deviceID == "" || deviceID == "unknown" {
			probeCtx, cancel := context.WithTimeout(ctx, serialProbeTimeout)
			deviceID = device.SerialNumber(probeCtx, exec)
			cancel()
		}
	}
	if deviceID == "" || deviceID == "unknown" {
		log.Debug("run-gate: no usable device id — failing open")
		return Result{Skip: false, Reason: "no_device_id", WSL: wslWithOverride(WSLDirective{})}
	}

	log.Progress("Run gate: checking scan cadence with the dashboard...")
	directive, wslDirective, err := Checkin(ctx, config.APIEndpoint, config.APIKey, config.CustomerID, deviceID, st.LastFullRunAt)
	if err != nil {
		log.Progress("Run gate: dashboard check-in failed, using cached cadence: %v", err)
	} else {
		if wslDirective.Enabled {
			log.Progress("Run gate: WSL scanning enabled for this tenant (%s)", wslDirective.Reason)
		}
		in.Directive = &directive
		log.Progress("Run gate: dashboard directive: mode=%s reason=%s interval=%dm",
			directive.Mode, directive.Reason, directive.EffectiveIntervalMinutes)
		// Persist the resolved id + gating fields even on "full" answers so
		// skipped wakeups never re-probe and the offline fallback stays
		// current. Best-effort.
		if perr := recordCheckin(deviceID, directive, in.Now); perr != nil {
			log.Debug("run-gate: could not persist check-in state: %v", perr)
		}
	}
	if stOK {
		in.State = &st
	}

	dec := Decide(in)
	res := Result{Skip: dec.Skip, Reason: dec.Reason, WSL: wslWithOverride(wslDirective)}
	if dec.Skip {
		// Online skip: best-effort heartbeat so the console shows the agent
		// checked in and was told not to scan (a gated skip otherwise leaves no
		// server-side trace). Never affects the run. Offline skips don't beacon
		// — the device can't reach the backend anyway.
		if in.Directive != nil {
			if err := PostSkipBeacon(ctx, config.APIEndpoint, config.APIKey, config.CustomerID,
				deviceID, in.Directive.Reason, dec.NextEligibleAt); err != nil {
				log.Debug("run-gate: skip beacon not sent: %v", err)
			}
		}
		detail := "cadence is managed by your StepSecurity dashboard"
		if dec.NextEligibleAt > 0 {
			detail = fmt.Sprintf("next scan eligible at %s",
				time.Unix(dec.NextEligibleAt, 0).UTC().Format(time.RFC3339))
		}
		res.Detail = detail
	}
	return res
}

// wslWithOverride applies the local escape for WSL scanning. STEPSEC_FORCE_WSL_SCAN
// exists so a test machine can exercise the distro-scan path before any backend
// serves wsl_directive; it is the ONLY way to enable it without the directive,
// and it is deliberately separate from --force-scan (which bypasses cadence and
// must not silently switch on scanning inside a developer's Linux environment).
func wslWithOverride(d WSLDirective) WSLDirective {
	if os.Getenv("STEPSEC_FORCE_WSL_SCAN") == "1" {
		d.Enabled = true
		if d.Reason == "" {
			d.Reason = "env_override"
		}
	}
	return d
}
