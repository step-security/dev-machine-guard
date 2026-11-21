package devcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/step-security/dev-machine-guard/internal/atomicfile"
	"github.com/step-security/dev-machine-guard/internal/buildinfo"
	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// A scan takes most of a minute on a large home directory, so the overview,
// its drill-downs and searches share one for this long.
const cacheMaxAge = 15 * time.Minute

var cacheDir = os.UserCacheDir

type cachedReport struct {
	Key string `json:"key"`
	// ScanSeconds lets the next scan say roughly how long is left.
	ScanSeconds float64                `json:"scan_seconds"`
	Report      *model.DeveloperReport `json:"report"`
}

func cachePath() (string, error) {
	dir, err := cacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "stepsecurity-dev-machine-guard", "findings.json"), nil
}

// cacheKey changes with the agent, the report shape and every setting that
// decides what a scan covers.
func cacheKey(cfg *cli.Config) string {
	flag := func(v *bool) string {
		if v == nil {
			return "auto"
		}
		return fmt.Sprint(*v)
	}
	sum := sha256.Sum256(fmt.Appendf(nil, "%s|%d|%q|%s|%s|%s|%s|%s|%s|%v", buildinfo.Version, model.DeveloperReportSchemaVersion, cfg.SearchDirs,
		flag(cfg.EnableNPMScan), flag(cfg.EnableBrewScan), flag(cfg.EnablePythonScan), flag(cfg.EnableRuntimeScan),
		flag(cfg.IncludeTCCProtected), flag(cfg.IncludeNetworkVolumes), cfg.IncludeBundledPlugins))
	return hex.EncodeToString(sum[:])
}

func readCache() (c cachedReport) {
	path, err := cachePath()
	if err != nil {
		return c
	}
	data, err := os.ReadFile(path) // #nosec G304 -- fixed name under the user's own cache directory
	if err != nil || json.Unmarshal(data, &c) != nil {
		return cachedReport{}
	}
	return c
}

// lastScanDuration is how long the previous scan took, however old it is.
func lastScanDuration() time.Duration {
	return time.Duration(readCache().ScanSeconds * float64(time.Second))
}

func loadCache(key string, now time.Time) *model.DeveloperReport {
	c := readCache()
	if c.Key != key || c.Report == nil {
		return nil
	}
	scanned, err := time.Parse(time.RFC3339, c.Report.ScannedAt)
	if err != nil || now.Before(scanned) || now.Sub(scanned) > cacheMaxAge {
		return nil
	}
	c.Report.Cached = true
	return c.Report
}

// saveCache is best effort: a read-only cache directory costs a rescan, not the report.
func saveCache(key string, report *model.DeveloperReport, took time.Duration) {
	path, err := cachePath()
	if err != nil {
		return
	}
	data, err := json.Marshal(cachedReport{Key: key, ScanSeconds: took.Seconds(), Report: report})
	if err != nil {
		return
	}
	if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
		return
	}
	_ = atomicfile.Replace(path, data, 0o600)
}
