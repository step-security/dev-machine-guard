package detector

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// sysPkgSpec defines how to detect and query a system package manager.
type sysPkgSpec struct {
	Name       string   // display name: "rpm", "dpkg", "pacman", "apk"
	Binary     string   // binary to look for in PATH
	VersionCmd []string // command + args to get version (e.g., ["--version"])
	ListCmd    []string // command + args to list installed packages
	ParseLine  func(line string) model.SystemPackage
}

var sysPkgSpecs = []sysPkgSpec{
	{
		// RPM: works on Fedora, RHEL, CentOS, SUSE, Amazon Linux
		// Fields: NAME, VERSION-RELEASE, ARCH, INSTALLTIME (epoch), SOURCERPM
		Name: "rpm", Binary: "rpm",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{SOURCERPM}\n"},
		ParseLine:  parseRPMLine,
	},
	{
		// dpkg: works on Debian, Ubuntu, Mint, Pop!_OS
		// Fields: Package, Version, Architecture, Source
		Name: "dpkg", Binary: "dpkg-query",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-W", "-f", "${Package}\t${Version}\t${Architecture}\t${Source}\n"},
		ParseLine:  parseDpkgLine,
	},
	{
		// pacman: Arch Linux, Manjaro, EndeavourOS
		// -Q only gives name+version; architecture requires -Qi which is too slow per-package.
		// We get arch from the version string suffix when present.
		Name: "pacman", Binary: "pacman",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-Q"},
		ParseLine:  parsePacmanLine,
	},
	{
		// apk: Alpine Linux
		// Format: "name-version arch {origin} (license)"
		Name: "apk", Binary: "apk",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"list", "--installed"},
		ParseLine:  parseApkLineRich,
	},
}

// SystemPkgDetector detects installed system packages on Linux.
type SystemPkgDetector struct {
	exec executor.Executor
}

func NewSystemPkgDetector(exec executor.Executor) *SystemPkgDetector {
	return &SystemPkgDetector{exec: exec}
}

// Detect finds the active system package manager and returns its info.
// Returns nil on non-Linux platforms or if no known PM is found.
func (d *SystemPkgDetector) Detect(ctx context.Context) *model.PkgManager {
	if d.exec.GOOS() != model.PlatformLinux {
		return nil
	}

	for _, spec := range sysPkgSpecs {
		path, err := d.exec.LookPath(spec.Binary)
		if err != nil {
			continue
		}

		version := "unknown"
		stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 10*time.Second, spec.Binary, spec.VersionCmd...)
		if err == nil && exitCode == 0 {
			if line := strings.TrimSpace(strings.SplitN(stdout, "\n", 2)[0]); line != "" {
				version = line
			}
		}

		return &model.PkgManager{
			Name:    spec.Name,
			Version: version,
			Path:    path,
		}
	}

	return nil
}

// ListPackages returns all installed system packages.
// Uses the first detected package manager from sysPkgSpecs.
func (d *SystemPkgDetector) ListPackages(ctx context.Context) []model.SystemPackage {
	if d.exec.GOOS() != model.PlatformLinux {
		return nil
	}

	for _, spec := range sysPkgSpecs {
		if _, err := d.exec.LookPath(spec.Binary); err != nil {
			continue
		}

		stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 60*time.Second, spec.Binary, spec.ListCmd...)
		if err != nil || exitCode != 0 {
			return nil
		}

		return parsePackageList(stdout, spec.ParseLine)
	}

	return nil
}

func parsePackageList(stdout string, parseLine func(string) model.SystemPackage) []model.SystemPackage {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}

	var packages []model.SystemPackage
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pkg := parseLine(line)
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
	}
	return packages
}

// DetectAdditionalManagers returns snap and/or flatpak if installed.
// These coexist with the system PM — a machine can have rpm + snap + flatpak.
func (d *SystemPkgDetector) DetectAdditionalManagers(ctx context.Context) []model.PkgManager {
	if d.exec.GOOS() != model.PlatformLinux {
		return nil
	}

	type additionalPM struct {
		name       string
		binary     string
		versionCmd []string
	}

	candidates := []additionalPM{
		{"snap", "snap", []string{"version"}},
		{"flatpak", "flatpak", []string{"--version"}},
	}

	var managers []model.PkgManager
	for _, pm := range candidates {
		path, err := d.exec.LookPath(pm.binary)
		if err != nil {
			continue
		}

		version := "unknown"
		stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 10*time.Second, pm.binary, pm.versionCmd...)
		if err == nil && exitCode == 0 {
			if line := strings.TrimSpace(strings.SplitN(stdout, "\n", 2)[0]); line != "" {
				version = line
			}
		}

		managers = append(managers, model.PkgManager{
			Name:    pm.name,
			Version: version,
			Path:    path,
		})
	}

	return managers
}

// ListSnapPackages returns installed snap packages.
func (d *SystemPkgDetector) ListSnapPackages(ctx context.Context) []model.SystemPackage {
	if _, err := d.exec.LookPath("snap"); err != nil {
		return nil
	}

	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "snap", "list")
	if err != nil || exitCode != 0 {
		return nil
	}

	// snap list output: "Name  Version  Rev  Tracking  Publisher  Notes"
	// Skip the header line
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		return nil
	}

	var packages []model.SystemPackage
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pkg := model.SystemPackage{
				Name:    fields[0],
				Version: fields[1],
			}
			// Publisher is column 5 (0-indexed: 4)
			if len(fields) >= 5 {
				pkg.Source = fields[4] // publisher name
			}
			packages = append(packages, pkg)
		}
	}
	return packages
}

// ListFlatpakPackages returns installed flatpak applications.
func (d *SystemPkgDetector) ListFlatpakPackages(ctx context.Context) []model.SystemPackage {
	if _, err := d.exec.LookPath("flatpak"); err != nil {
		return nil
	}

	// Columns: application, version, arch, origin
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 30*time.Second,
		"flatpak", "list", "--app", "--columns=application,version,arch,origin")
	if err != nil || exitCode != 0 {
		return nil
	}

	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}

	var packages []model.SystemPackage
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format: "app.id\tversion\tarch\torigin" (tab-separated)
		parts := strings.Split(line, "\t")
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		pkg := model.SystemPackage{Name: parts[0]}
		if len(parts) >= 2 && parts[1] != "" {
			pkg.Version = parts[1]
		} else {
			pkg.Version = "unknown"
		}
		if len(parts) >= 3 {
			pkg.Arch = parts[2]
		}
		if len(parts) >= 4 {
			pkg.Source = parts[3] // e.g. "flathub"
		}
		packages = append(packages, pkg)
	}
	return packages
}

// ---------- Per-PM line parsers ----------

// parseRPMLine parses tab-separated: NAME\tVERSION-RELEASE\tARCH\tINSTALLTIME\tSOURCERPM
func parseRPMLine(line string) model.SystemPackage {
	parts := strings.Split(line, "\t")
	pkg := model.SystemPackage{}
	if len(parts) >= 1 {
		pkg.Name = parts[0]
	}
	if len(parts) >= 2 {
		pkg.Version = parts[1]
	}
	if len(parts) >= 3 {
		pkg.Arch = parts[2]
	}
	if len(parts) >= 4 {
		if ts, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
			pkg.InstallTimeUnix = ts
		}
	}
	if len(parts) >= 5 && parts[4] != "(none)" {
		pkg.Source = parts[4]
	}
	return pkg
}

// parseDpkgLine parses tab-separated: Package\tVersion\tArchitecture\tSource
func parseDpkgLine(line string) model.SystemPackage {
	parts := strings.Split(line, "\t")
	pkg := model.SystemPackage{}
	if len(parts) >= 1 {
		pkg.Name = parts[0]
	}
	if len(parts) >= 2 {
		pkg.Version = parts[1]
	}
	if len(parts) >= 3 {
		pkg.Arch = parts[2]
	}
	if len(parts) >= 4 && parts[3] != "" {
		pkg.Source = parts[3]
	}
	return pkg
}

// parsePacmanLine parses space-separated: name version
// pacman -Q only gives name + version; no arch/source without -Qi (too slow).
func parsePacmanLine(line string) model.SystemPackage {
	parts := strings.SplitN(line, " ", 2)
	pkg := model.SystemPackage{}
	if len(parts) >= 1 {
		pkg.Name = parts[0]
	}
	if len(parts) >= 2 {
		pkg.Version = parts[1]
	}
	return pkg
}

// parseApkLineRich parses apk's "name-version arch {origin} (license)" format.
// Example: "curl-8.9.1-r2 x86_64 {curl} (MIT)"
func parseApkLineRich(line string) model.SystemPackage {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return model.SystemPackage{}
	}

	pkg := model.SystemPackage{}

	// Extract arch (second field)
	if len(fields) >= 2 {
		pkg.Arch = fields[1]
	}

	// Extract origin (field in curly braces: {origin})
	for _, f := range fields {
		if strings.HasPrefix(f, "{") && strings.HasSuffix(f, "}") {
			pkg.Source = f[1 : len(f)-1]
			break
		}
	}

	// Parse name-version from first field
	nameVer := fields[0]
	lastDash := strings.LastIndex(nameVer, "-")
	if lastDash <= 0 {
		pkg.Name = nameVer
		pkg.Version = "unknown"
		return pkg
	}
	rest := nameVer[lastDash+1:]
	if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		pkg.Name = nameVer[:lastDash]
		pkg.Version = rest
		return pkg
	}
	secondDash := strings.LastIndex(nameVer[:lastDash], "-")
	if secondDash > 0 {
		pkg.Name = nameVer[:secondDash]
		pkg.Version = nameVer[secondDash+1:]
		return pkg
	}
	pkg.Name = nameVer
	pkg.Version = "unknown"
	return pkg
}
