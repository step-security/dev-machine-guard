package telemetry

import (
	"os"
	"time"
)

// defaultScanDeadline caps how long a single scan can run before the agent
// gives up and reports failure. Chosen empirically from production heartbeat
// data: healthy scans on big monorepos finish in under 30 minutes; runs
// stuck on hung subprocesses have been observed lasting 6+ hours. 60 minutes
// is well clear of the legitimate tail while still bounded enough to keep
// the daily launchd/schtasks/systemd firing useful as a retry mechanism.
const defaultScanDeadline = 60 * time.Minute

// scanDeadlineFromEnv resolves the effective scan deadline from the
// STEPSEC_MAX_SCAN_DURATION environment variable, falling back to def.
//
// Accepted values:
//   - unset / empty: returns def
//   - "0" / "off": returns 0 (no deadline — caller must skip the
//     context.WithTimeout wrap)
//   - any Go time.ParseDuration string ("45m", "2h", "30m45s"): that
//     duration, when positive
//   - anything else: returns def (silent fallback — telemetry runs from
//     unattended scheduler contexts where a config typo should not be
//     fatal to the scan)
func scanDeadlineFromEnv(def time.Duration) time.Duration {
	v := os.Getenv("STEPSEC_MAX_SCAN_DURATION")
	if v == "" {
		return def
	}
	if v == "0" || v == "off" {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}
