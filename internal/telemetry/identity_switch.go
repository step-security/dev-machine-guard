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
// is retired once with reason identity_changed. Best effort: a failure is a
// warning, the backend's auto-retire or an admin can still remove the row,
// and the marker keeps the retire from being re-attempted once it succeeds.
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
	rctx, cancel := context.WithTimeout(ctx, identitySwitchBudget)
	defer cancel()
	err := retire.Post(rctx, config.APIEndpoint, config.APIKey, config.CustomerID, dev.SerialNumber,
		buildinfo.Version, exec.GOOS(), retire.ReasonIdentityChanged)
	if err != nil {
		log.Warn("identity switch: could not retire the previous device row %s: %v (auto-retire or the dashboard can still remove it)", dev.SerialNumber, err)
		return
	}
	if merr := device.MarkSerialRowRetired(dev.SerialNumber); merr != nil {
		log.Debug("identity switch: could not record the retire: %v", merr)
	}
	log.Progress("Identity switch: this host is now multi-user; retired its previous device row %s (reason identity_changed)", dev.SerialNumber)
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
