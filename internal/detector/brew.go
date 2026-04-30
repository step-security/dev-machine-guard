package detector

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// BrewDetector detects Homebrew installation and packages.
type BrewDetector struct {
	exec executor.Executor
}

func NewBrewDetector(exec executor.Executor) *BrewDetector {
	return &BrewDetector{exec: exec}
}

// DetectBrew checks if Homebrew is installed and returns its version info.
// Returns nil if Homebrew is not found.
func (d *BrewDetector) DetectBrew(ctx context.Context) *model.PkgManager {
	path, err := d.exec.LookPath("brew")
	if err != nil {
		return nil
	}

	version := "unknown"
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 10*time.Second, "brew", "--version")
	if err == nil {
		// "brew --version" outputs "Homebrew 4.3.5\n..."
		if line := firstLine(stdout); line != "" {
			version = strings.TrimPrefix(line, "Homebrew ")
		}
	}

	return &model.PkgManager{
		Name:    "homebrew",
		Version: version,
		Path:    path,
	}
}

// ListFormulae returns installed Homebrew formulae with versions.
func (d *BrewDetector) ListFormulae(ctx context.Context) []model.BrewPackage {
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "brew", "list", "--formula", "--versions")
	if err != nil {
		return nil
	}
	return parseBrewList(stdout)
}

// ListCasks returns installed Homebrew casks with versions.
func (d *BrewDetector) ListCasks(ctx context.Context) []model.BrewPackage {
	stdout, _, _, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "brew", "list", "--cask", "--versions")
	if err != nil {
		return nil
	}
	return parseBrewList(stdout)
}

// parseBrewList parses "name version" lines from `brew list --versions` output.
func parseBrewList(stdout string) []model.BrewPackage {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}
	var packages []model.BrewPackage
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "name version [version2 ...]"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			packages = append(packages, model.BrewPackage{
				Name:    parts[0],
				Version: parts[1],
			})
		} else if len(parts) == 1 {
			packages = append(packages, model.BrewPackage{
				Name:    parts[0],
				Version: "unknown",
			})
		}
	}
	return packages
}

// ListFormulaeRich returns installed formulae with metadata.
// Uses two sources:
//  1. brew info --json=v2 for desc/license/homepage (subprocess, but comprehensive)
//  2. INSTALL_RECEIPT.json from Cellar for tap/install_time/dependency (file read, fast)
//
// Falls back gracefully: if JSON command fails, reads receipts only.
// If receipts fail, falls back to basic `brew list --versions`.
func (d *BrewDetector) ListFormulaeRich(ctx context.Context) []model.BrewPackage {
	// Try brew info --json=v2 first (gets everything in one shot)
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 60*time.Second,
		"brew", "info", "--json=v2", "--installed", "--formula")
	if err == nil && exitCode == 0 {
		pkgs, parseErr := parseBrewInfoJSON(stdout, "formula")
		if parseErr == nil && len(pkgs) > 0 {
			return pkgs
		}
	}

	// Fallback: basic list + receipt enrichment
	pkgs := d.ListFormulae(ctx)
	if len(pkgs) == 0 {
		return nil
	}
	d.enrichFromReceipts(pkgs, "formula")
	return pkgs
}

// ListCasksRich returns installed casks with metadata.
// Same strategy as ListFormulaeRich.
func (d *BrewDetector) ListCasksRich(ctx context.Context) []model.BrewPackage {
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 60*time.Second,
		"brew", "info", "--json=v2", "--installed", "--cask")
	if err == nil && exitCode == 0 {
		pkgs, parseErr := parseBrewInfoJSON(stdout, "cask")
		if parseErr == nil && len(pkgs) > 0 {
			return pkgs
		}
	}

	pkgs := d.ListCasks(ctx)
	if len(pkgs) == 0 {
		return nil
	}
	d.enrichFromReceipts(pkgs, "cask")
	return pkgs
}

// enrichFromReceipts reads INSTALL_RECEIPT.json from disk and populates
// tap, install time, and dependency status. No subprocess needed.
func (d *BrewDetector) enrichFromReceipts(pkgs []model.BrewPackage, kind string) {
	prefix := d.brewPrefix()
	if prefix == "" {
		return
	}

	for i := range pkgs {
		var receiptPath string
		if kind == "formula" {
			// /opt/homebrew/Cellar/{name}/{version}/INSTALL_RECEIPT.json
			receiptPath = prefix + "/Cellar/" + pkgs[i].Name + "/" + pkgs[i].Version + "/INSTALL_RECEIPT.json"
		} else {
			// /opt/homebrew/Caskroom/{name}/.metadata/INSTALL_RECEIPT.json
			receiptPath = prefix + "/Caskroom/" + pkgs[i].Name + "/.metadata/INSTALL_RECEIPT.json"
		}

		data, err := d.exec.ReadFile(receiptPath)
		if err != nil {
			continue
		}

		var receipt brewReceipt
		if json.Unmarshal(data, &receipt) != nil {
			continue
		}

		pkgs[i].Tap = receipt.Source.Tap
		pkgs[i].InstallTimeUnix = receipt.Time
		pkgs[i].InstalledAsDependency = receipt.InstalledAsDependency
		pkgs[i].PouredFromBottle = receipt.PouredFromBottle
	}
}

// brewPrefix returns the Homebrew prefix path.
func (d *BrewDetector) brewPrefix() string {
	// Standard locations
	for _, p := range []string{"/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"} {
		if d.exec.DirExists(p+"/Cellar") || d.exec.DirExists(p+"/Caskroom") {
			return p
		}
	}
	return ""
}

// brewReceipt represents the INSTALL_RECEIPT.json structure.
type brewReceipt struct {
	Time                  int64 `json:"time"`
	InstalledAsDependency bool  `json:"installed_as_dependency"`
	PouredFromBottle      bool  `json:"poured_from_bottle"`
	Source                struct {
		Tap string `json:"tap"`
	} `json:"source"`
}

// brewInfoV2 represents the top-level structure of `brew info --json=v2` output.
type brewInfoV2 struct {
	Formulae []brewFormula `json:"formulae"`
	Casks    []brewCask    `json:"casks"`
}

type brewFormula struct {
	Name      string `json:"name"`
	Tap       string `json:"tap"`
	Desc      string `json:"desc"`
	License   string `json:"license"`
	Homepage  string `json:"homepage"`
	Deprecated bool  `json:"deprecated"`
	Installed []struct {
		Version               string `json:"version"`
		Time                  int64  `json:"time"`
		InstalledAsDependency bool   `json:"installed_as_dependency"`
		PouredFromBottle      bool   `json:"poured_from_bottle"`
	} `json:"installed"`
}

type brewCask struct {
	Token         string   `json:"token"`
	Name          []string `json:"name"`
	Tap           string   `json:"tap"`
	Desc          string   `json:"desc"`
	Homepage      string   `json:"homepage"`
	Version       string   `json:"version"`
	Installed     string   `json:"installed"`
	InstalledTime int64    `json:"installed_time"`
	Deprecated    bool     `json:"deprecated"`
	AutoUpdates   bool     `json:"auto_updates"`
}

// parseBrewInfoJSON parses brew info --json=v2 output into BrewPackages.
func parseBrewInfoJSON(stdout string, kind string) ([]model.BrewPackage, error) {
	var info brewInfoV2
	if err := json.Unmarshal([]byte(stdout), &info); err != nil {
		return nil, err
	}

	var packages []model.BrewPackage

	if kind == "formula" {
		for _, f := range info.Formulae {
			if len(f.Installed) == 0 {
				continue
			}
			inst := f.Installed[0] // use the first (most recent) installation
			packages = append(packages, model.BrewPackage{
				Name:                  f.Name,
				Version:               inst.Version,
				Tap:                   f.Tap,
				Description:           f.Desc,
				License:               f.License,
				Homepage:              f.Homepage,
				InstallTimeUnix:       inst.Time,
				InstalledAsDependency: inst.InstalledAsDependency,
				Deprecated:            f.Deprecated,
				PouredFromBottle:      inst.PouredFromBottle,
			})
		}
	} else {
		for _, c := range info.Casks {
			version := c.Installed
			if version == "" {
				version = c.Version
			}
			desc := c.Desc
			if desc == "" && len(c.Name) > 0 {
				desc = c.Name[0]
			}
			packages = append(packages, model.BrewPackage{
				Name:            c.Token,
				Version:         version,
				Tap:             c.Tap,
				Description:     desc,
				Homepage:        c.Homepage,
				InstallTimeUnix: c.InstalledTime,
				Deprecated:      c.Deprecated,
				AutoUpdates:     c.AutoUpdates,
			})
		}
	}

	return packages, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
