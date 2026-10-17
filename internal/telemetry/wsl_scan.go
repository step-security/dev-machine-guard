package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/config"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/wslagent"
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

// wslLinuxBinaryEnv overrides where the Linux agent binary is found, for a
// test machine pointing at a local build. Nothing is downloaded when it is set.
const wslLinuxBinaryEnv = "STEPSEC_WSL_LINUX_BINARY"

// wslLinuxBinaryAltName is an older name looked for next to the Windows agent
// when dmg-linux is absent. Never downloaded under this name.
const wslLinuxBinaryAltName = "stepsecurity-dev-machine-guard-linux"

// wslLinuxBinaryResolver finds, or installs, the Linux agent binary. A
// variable so tests can keep the download out of unit runs.
var wslLinuxBinaryResolver = wslLinuxBinaryPath

// wslLinuxAgentEnsure downloads the Linux agent when no installer provided
// one. A variable so tests can check what is asked for without the network.
var wslLinuxAgentEnsure = func(ctx context.Context, dir, version, arch string) (string, bool, error) {
	return wslagent.New().Ensure(ctx, dir, version, arch)
}

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
func triggerWSLScans(ctx context.Context, exec executor.Executor, log *progress.Logger, cfg *cli.Config, dev *model.Device) []wslScanResult {
	if cfg == nil || !cfg.WSLScanEnabled {
		return nil
	}
	if dev == nil || dev.WSL == nil || dev.WSL.Presence != model.WSLPresenceYes || len(dev.WSL.Distros) == 0 {
		return nil
	}
	hostID := device.ID(*dev)
	if hostID == "" || hostID == "unknown" {
		// Without a host id the guest cannot be paired to anything, so a scan
		// would produce an unattributable device record.
		log.Warn("WSL scan: host has no usable device ID — not triggering distro scans")
		return nil
	}

	// Resolve the binary only when some distro will actually be launched, so
	// a host whose distros are all stopped never downloads it.
	linuxBin := ""
	if anyLaunchableDistro(dev.WSL.Distros) {
		linuxBin = wslLinuxBinaryResolver(ctx, exec, log)
		if linuxBin == "" {
			log.Warn("WSL scan: no Linux agent binary available next to the agent (set %s), skipping", wslLinuxBinaryEnv)
			return nil
		}
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
				"--wsl-host-serial="+hostID,
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

// anyLaunchableDistro reports whether the loop below would launch at least
// one distro. Mirrors its skip cases.
func anyLaunchableDistro(distros []model.WSLDistro) bool {
	for _, d := range distros {
		if d.Running && d.DistroID != "" && (d.DefaultUID == nil || *d.DefaultUID != 0) {
			return true
		}
	}
	return false
}

// wslLinuxBinaryPath locates the Linux agent binary on the Windows host. The
// env override wins; otherwise look beside the running executable, where the
// MSI and the loader install dmg-linux. When neither did (binary-only
// installs, older loaders), download the signed release binary for this
// agent's version into the same place. Returns "" when there is nothing to
// run.
func wslLinuxBinaryPath(ctx context.Context, exec executor.Executor, log *progress.Logger) string {
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
	if !exec.FileExists(filepath.Join(dir, wslagent.BinaryName)) {
		if alt := filepath.Join(dir, wslLinuxBinaryAltName); exec.FileExists(alt) {
			return alt
		}
	}

	path, downloaded, err := wslLinuxAgentEnsure(ctx, dir, buildinfo.Version, wslagent.NativeArch())
	switch {
	case err != nil && path != "":
		log.Warn("WSL scan: could not update the Linux agent (%v); using the existing copy", err)
	case err != nil:
		log.Warn("WSL scan: could not install the Linux agent: %v", err)
	case downloaded:
		log.Progress("WSL scan: installed Linux agent v%s at %s", buildinfo.Version, path)
	}
	return path
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
