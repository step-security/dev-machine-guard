package telemetry

import (
	"strings"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// wslGuestFromConfig returns the guest block when this run was triggered inside
// a WSL distro. Both values are required: a host id without a distro id (or the
// reverse) cannot identify anything, so a partial pair is treated as "not a
// guest" rather than half-identified.
func wslGuestFromConfig(cfg *cli.Config) *model.WSLGuest {
	if cfg == nil {
		return nil
	}
	host := strings.TrimSpace(cfg.WSLHostSerial)
	distro := strings.TrimSpace(cfg.WSLDistroID)
	if host == "" || distro == "" {
		return nil
	}
	return &model.WSLGuest{HostDeviceID: host, DistroID: distro}
}
