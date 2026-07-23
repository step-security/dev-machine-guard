package rungate

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/featuregate"
	"github.com/step-security/dev-machine-guard/internal/lock"
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
}

// Evaluate runs the whole gate ahead of telemetry.Run: explicit escapes, a
// quiet lock peek, cached-or-probed device id, the backend check-in, the
// decision, and state persistence. It makes AT MOST one network call (none
// when an escape or the lock peek short-circuits) and NEVER fails the run —
// every error path degrades to Skip=false.
func Evaluate(ctx context.Context, exec executor.Executor, log *progress.Logger, forceScan bool) Result {
	in := Inputs{
		ForceScan:      forceScan || os.Getenv("STEPSEC_FORCE_SCAN") == "1",
		FeatureEnabled: featuregate.IsEnabled(featuregate.FeatureRunGate),
		KillSwitch:     os.Getenv("STEPSEC_DISABLE_RUN_GATE") == "1",
		Now:            time.Now(),
	}

	// Escapes need no I/O at all; resolve them before touching disk or lock.
	if dec := Decide(in); !dec.Skip && (in.ForceScan || !in.FeatureEnabled || in.KillSwitch) {
		if in.ForceScan && in.FeatureEnabled {
			log.Progress("Run gate: bypassed (--force-scan)")
		}
		return Result{Skip: false, Reason: dec.Reason}
	}

	// Quiet collision back-off: another instance is mid-scan. Skipping here —
	// before any network call — is what keeps hourly wakeups overlapping a
	// long scan from posting the lock-contention failure beacon every hour.
	if pid, alive := lock.Holder(); alive {
		in.LockHeldByLivePID = true
		dec := Decide(in)
		return Result{
			Skip:   dec.Skip,
			Reason: dec.Reason,
			Detail: fmt.Sprintf("another instance is scanning (PID %d)", pid),
		}
	}

	// Device id: cached from a prior run when possible, else a bounded local
	// probe. Without a real serial the backend can't be asked anything
	// meaningful — fail open rather than gate on a bogus id.
	st, stOK := readState()
	deviceID := st.DeviceID
	if deviceID == "" || deviceID == "unknown" {
		probeCtx, cancel := context.WithTimeout(ctx, serialProbeTimeout)
		deviceID = device.SerialNumber(probeCtx, exec)
		cancel()
	}
	if deviceID == "" || deviceID == "unknown" {
		log.Debug("run-gate: no usable device id — failing open")
		return Result{Skip: false, Reason: "no_device_id"}
	}

	directive, err := Checkin(ctx, config.APIEndpoint, config.APIKey, config.CustomerID, deviceID, st.LastFullRunAt)
	if err != nil {
		log.Debug("run-gate: check-in failed (%v) — deciding from cached state", err)
	} else {
		in.Directive = &directive
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
	res := Result{Skip: dec.Skip, Reason: dec.Reason}
	if dec.Skip {
		detail := "cadence is managed by your StepSecurity dashboard"
		if dec.NextEligibleAt > 0 {
			detail = fmt.Sprintf("next scan eligible at %s",
				time.Unix(dec.NextEligibleAt, 0).UTC().Format(time.RFC3339))
		}
		res.Detail = detail
	}
	return res
}
