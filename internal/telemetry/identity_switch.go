package telemetry

import (
	"context"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/heartbeat"
	"github.com/step-security/dev-machine-guard/internal/lock"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/retire"
)

// identitySwitchBudget bounds the whole retire-on-switch step (two 2s
// attempts inside retire.Post); it must never hold the scan.
const identitySwitchBudget = 5 * time.Second

// retireSerialRowOnIdentitySwitch finishes the one-time switch to the
// automatic per-user identity: the host used to report under its machine
// identity (serial), that row would otherwise linger as a stale seat, so it
// is removed once through the retire API with reason identity_changed. The
// backend treats that reason as a removal from the customer's view: the row
// is hidden everywhere at once (a "retired" twin of a live per-user device
// would only confuse) and purged after the standard retention; the reason is
// accepted only for the machine-identity row. Best effort: a failure
// is a warning, the backend's auto-retire or an admin can still remove the
// row, and the marker keeps the call from being re-attempted once it
// succeeds.
// Never runs for WSL guests (their identity is the host's) or when no
// enterprise config exists.
func retireSerialRowOnIdentitySwitch(ctx context.Context, exec executor.Executor, log *progress.Logger, dev *model.Device, wslGuest *model.WSLGuest) {
	if dev == nil || wslGuest != nil || dev.DeviceIDSource != device.IdentitySourceAuto {
		return
	}
	if !device.SerialRowRetirePending(dev.SerialNumber, machineLastRunDeviceID()) {
		return
	}
	if !config.IsEnterpriseMode() {
		return
	}
	// A scan that started under the previous identity holds the machine-wide
	// lock until it has reported. Retiring now would be undone by its upload,
	// and the marker would then keep the retire from ever being retried, so
	// the retire waits for a later run instead.
	shared, lerr := lock.AcquireMachineWide()
	if lerr != nil {
		log.Progress("Identity switch: a scan under the previous identity %s is still running; its row is retired on a later run", dev.SerialNumber)
		return
	}
	defer shared.Release()
	rctx, cancel := context.WithTimeout(ctx, identitySwitchBudget)
	defer cancel()
	status, err := retire.Post(rctx, config.APIEndpoint, config.APIKey, config.CustomerID, dev.SerialNumber,
		buildinfo.Version, exec.GOOS(), retire.ReasonIdentityChanged)
	if err != nil {
		log.Warn("identity switch: could not remove the previous device row %s: %v (auto-retire or the dashboard can still remove it)", dev.SerialNumber, err)
		return
	}
	if status == retire.StatusOutOfScope {
		// Not recorded in the marker: once an admin widens the scope (or
		// tags this host), the next run removes the row without a reinstall.
		log.Progress("Identity switch: previous device row %s is outside the dashboard's retirement scope; left in place", dev.SerialNumber)
		return
	}
	if merr := device.MarkSerialRowRetired(dev.SerialNumber); merr != nil {
		log.Debug("identity switch: could not record the retire: %v", merr)
	}
	log.Progress("Identity switch: this host is now multi-user; removed its previous device row %s (reason identity_changed)", dev.SerialNumber)
}

// machineLastRunDeviceID is the device id the machine-wide last-run.json last
// checked in under, "" when there is none. An upgraded single-user host still
// carries its serial there, which is how the switch knows a serial row exists.
func machineLastRunDeviceID() string {
	dir := device.MachineStateDir()
	if dir == "" {
		return ""
	}
	rec, err := heartbeat.Load(filepath.Join(dir, heartbeat.Filename))
	if err != nil || rec == nil || rec.RunGate == nil {
		return ""
	}
	return rec.RunGate.DeviceID
}

// serialRunSuperseded reports whether this run, which resolved the machine
// identity before taking the instance lock, was overtaken by another user's
// switch to per-user identities meanwhile (device.AutoIdentitySuperseded).
// Such a run is skipped: its upload would restore the serial row the switch
// just retired, and the marker would then keep that row from being retired
// again. WSL guests report under their host's identity and are never skipped.
func serialRunSuperseded(exec executor.Executor, ident device.Identity, wslGuest *model.WSLGuest) bool {
	if wslGuest != nil || ident.Source != device.IdentitySourceSerial {
		return false
	}
	// A service-account run in automatic mode (AutoFallback) is overtaken
	// the moment the per-user runs retire the serial row; the marker is
	// re-read here, after the lock, so a retire that landed while this run
	// was resolving its identity is seen.
	if ident.AutoFallback {
		return device.AutoSerialRowRetired(exec)
	}
	return device.AutoIdentitySuperseded(exec)
}
