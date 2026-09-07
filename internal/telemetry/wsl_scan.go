package telemetry

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Per-distro outcomes of the trigger phase. The host only ever learns whether
// a scan *started* — the distro's own agent reports what it found — so these
// describe launching, not scanning.
const (
	wslScanLaunched          = "launched"
	wslScanSkippedNotRunning = "skipped_not_running"
	wslScanSkippedNoUser     = "skipped_no_user"
	wslScanSkippedNoDistroID = "skipped_no_distro_id"
	wslScanFailed            = "failed"
)

// wslLinuxBinaryEnv overrides where the Linux agent binary is found. Delivery
// of that binary to a Windows host is not built yet, so this is how a test
// machine points at one.
const wslLinuxBinaryEnv = "STEPSEC_WSL_LINUX_BINARY"

// wslLinuxBinaryNames are the names looked for next to the Windows agent.
var wslLinuxBinaryNames = []string{"dmg-linux", "stepsecurity-dev-machine-guard-linux"}

// wslScanResult is one distro's trigger outcome.
type wslScanResult struct {
	Distro   string
	DistroID string
	Outcome  string
	Err      string
}

// triggerWSLScans starts a scan inside every running WSL distribution, and
// waits only long enough to know each one started.
//
// It does not collect results. The distro's agent owns its own upload, so a
// scan that takes minutes cannot extend this run — and it must not, because
// the relay it spawns has to outlive this process (WSL tears a distro down
// shortly after its last Windows-side client exits, so the relay is the scan's
// life support, and detaching inside Linux does not help).
//
// Returns one result per registered distro, for the log. Never errors: a
// failure to launch one distro must not affect the host's own scan.
func triggerWSLScans(exec executor.Executor, log *progress.Logger, cfg *cli.Config, dev *model.Device) []wslScanResult {
	if cfg == nil || !cfg.WSLScanEnabled {
		return nil
	}
	if dev == nil || dev.WSL == nil || dev.WSL.Presence != model.WSLPresenceYes || len(dev.WSL.Distros) == 0 {
		return nil
	}
	if dev.SerialNumber == "" || dev.SerialNumber == "unknown" {
		// Without a host id the guest cannot be paired to anything, so a scan
		// would produce an unattributable device record.
		log.Warn("WSL scan: host has no usable serial — not triggering distro scans")
		return nil
	}

	linuxBin := wslLinuxBinaryPath(exec)
	if linuxBin == "" {
		log.Warn("WSL scan: no Linux agent binary found next to the agent (set %s) — skipping", wslLinuxBinaryEnv)
		return nil
	}
	guestConfig := windowsPathToWSL(config.ConfigFilePath())

	results := make([]wslScanResult, 0, len(dev.WSL.Distros))
	for _, d := range dev.WSL.Distros {
		res := wslScanResult{Distro: d.Name, DistroID: d.DistroID}
		switch {
		case !d.Running:
			// The normal case, and a product promise: we never start a stopped
			// distro. `wsl -e` would boot one, so this check is the whole
			// enforcement.
			res.Outcome = wslScanSkippedNotRunning
		case d.DistroID == "":
			res.Outcome = wslScanSkippedNoDistroID
		case d.DefaultUID != nil && *d.DefaultUID == 0:
			// Root-only distro: its home holds nothing worth scanning, and a
			// scan there would report a clean machine.
			res.Outcome = wslScanSkippedNoUser
		default:
			// No -u: `wsl -e` already runs as the distro's default user, which
			// is whose home we want. No --force-scan either: the guest gates
			// itself on the tenant's cadence, checking in under the derived
			// guest id we hand it, so a distro scanned an hour ago skips.
			err := exec.StartDetached("wsl.exe",
				"-d", d.Name,
				"-e", windowsPathToWSL(linuxBin),
				"send-telemetry",
				"--config="+guestConfig,
				"--wsl-host-serial="+dev.SerialNumber,
				"--wsl-distro-id="+d.DistroID,
			)
			if err != nil {
				res.Outcome = wslScanFailed
				res.Err = err.Error()
			} else {
				res.Outcome = wslScanLaunched
			}
		}
		results = append(results, res)
		logWSLScanResult(log, res)
	}
	return results
}

func logWSLScanResult(log *progress.Logger, res wslScanResult) {
	switch res.Outcome {
	case wslScanLaunched:
		log.Progress("  %s: scan launched", res.Distro)
	case wslScanFailed:
		log.Warn("  %s: could not launch scan: %s", res.Distro, res.Err)
	default:
		log.Progress("  %s: %s", res.Distro, res.Outcome)
	}
}

// wslLinuxBinaryPath locates the Linux agent binary on the Windows host. The
// env override wins; otherwise look beside the running executable. Returns ""
// when there is nothing to run, which is the current default — host-side
// delivery of the Linux binary is not implemented.
func wslLinuxBinaryPath(exec executor.Executor) string {
	if p := strings.TrimSpace(os.Getenv(wslLinuxBinaryEnv)); p != "" {
		if exec.FileExists(p) {
			return p
		}
		return ""
	}
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(self)
	for _, name := range wslLinuxBinaryNames {
		p := filepath.Join(dir, name)
		if exec.FileExists(p) {
			return p
		}
	}
	return ""
}

// windowsPathToWSL rewrites a Windows path to the form a distro sees over the
// automatic drive mount: C:\ProgramData\x -> /mnt/c/ProgramData/x. A path that
// is already POSIX-shaped is returned unchanged, so callers need not care which
// they hold.
//
// If a distro has automounting disabled the translated path will not exist
// there; the launch then fails and is reported as such, which is cheaper than
// probing every distro for its mount config.
func windowsPathToWSL(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || strings.HasPrefix(p, "/") {
		return p
	}
	if len(p) >= 2 && p[1] == ':' {
		drive := strings.ToLower(p[:1])
		rest := strings.ReplaceAll(p[2:], `\`, "/")
		return "/mnt/" + drive + strings.TrimSuffix("/"+strings.TrimPrefix(rest, "/"), "/")
	}
	return strings.ReplaceAll(p, `\`, "/")
}
