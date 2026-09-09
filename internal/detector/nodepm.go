package detector

import (
	"context"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/execguard"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/versionmeta"
)

type pmSpec struct {
	Name       string
	Binary     string
	VersionCmd string
}

var packageManagers = []pmSpec{
	{"npm", "npm", "--version"},
	{"yarn", "yarn", "--version"},
	{"pnpm", "pnpm", "--version"},
	{"bun", "bun", "--version"},
}

// NodePMDetector detects installed Node.js package managers.
type NodePMDetector struct {
	exec executor.Executor
	log  *progress.Logger
}

func NewNodePMDetector(exec executor.Executor) *NodePMDetector {
	return &NodePMDetector{exec: exec, log: progress.NewNoop()}
}

// WithLogger injects a logger (used to surface exec fallbacks when metadata
// version resolution misses). Chainable, mirrors configaudit's WithSkipper.
func (d *NodePMDetector) WithLogger(log *progress.Logger) *NodePMDetector {
	if log != nil {
		d.log = log
	}
	return d
}

func (d *NodePMDetector) DetectManagers(ctx context.Context) []model.PkgManager {
	var results []model.PkgManager

	for _, pm := range packageManagers {
		// LookPath returns "" on error, so a failed lookup leaves path empty
		// and triggers the default-path fallback below rather than dropping
		// the manager outright.
		path, _ := d.exec.LookPath(pm.Binary)

		version := ""
		if path != "" {
			// Static-first, exec-last (AGENTS.md §3.4): the manager's own
			// package.json (npm/yarn/pnpm) or Homebrew layout (bun) carries
			// the version without launching anything.
			version = versionmeta.FromBinary(ctx, d.exec, path)
		}
		if path != "" && version == "" {
			if safe, reason := execguard.SafeToExec(ctx, d.exec, path); !safe {
				d.log.Warn("skipping %s version probe: %s", path, reason)
			} else {
				// Run the exact absolute path the guard assessed, not the bare
				// name — a PATH re-resolution at exec time could pick a
				// different (unassessed) binary.
				d.log.Progress("exec fallback: running %s %s (no metadata version source)", path, pm.VersionCmd)
				stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, path, pm.VersionCmd)
				if err == nil {
					version = strings.TrimSpace(stdout)
				}
			}
		}

		// Fallback: the binary wasn't on PATH, or it was but --version returned
		// nothing — both happen under launchd's stripped PATH when the login
		// shell sourcing doesn't surface the manager. Probe the OS-specific
		// default install dirs and run the binary by absolute path.
		if path == "" || version == "" {
			fbPath, fbVersion := resolveNodePMFromDefaults(ctx, d.exec, d.log, pm.Binary, pm.VersionCmd)
			if path == "" {
				path = fbPath
			}
			if version == "" {
				version = fbVersion
			}
		}

		// Found nowhere we know to look — not installed on this device.
		if path == "" {
			continue
		}

		if version == "" {
			version = "unknown"
		}

		results = append(results, model.PkgManager{
			Name:    pm.Name,
			Version: version,
			Path:    path,
		})
	}

	return results
}
