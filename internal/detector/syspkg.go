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
	// ParseBulk, when non-nil, replaces line-by-line parsing. It receives the
	// full stdout and returns all packages at once. Used by pacman -Qi which
	// outputs multi-line blocks rather than one-package-per-line.
	ParseBulk func(stdout string) []model.SystemPackage
}

var sysPkgSpecs = []sysPkgSpec{
	{
		// RPM: works on Fedora, RHEL, CentOS, SUSE, Amazon Linux
		// Fields: NAME, VERSION-RELEASE, ARCH, INSTALLTIME, SOURCERPM, VENDOR,
		//         PACKAGER, URL, LICENSE, BUILDTIME, SIZE, SIGPGP, RSAHEADER
		Name: "rpm", Binary: "rpm",
		VersionCmd: []string{"--version"},
		ListCmd: []string{"-qa", "--queryformat",
			"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{SOURCERPM}\t" +
				"%{VENDOR}\t%{PACKAGER}\t%{URL}\t%{LICENSE}\t%{BUILDTIME}\t%{SIZE}\t" +
				"%{SIGPGP:pgpsig}\t%{RSAHEADER:pgpsig}\n"},
		ParseLine: parseRPMLine,
	},
	{
		// dpkg: works on Debian, Ubuntu, Mint, Pop!_OS
		// Fields: Package, Version, Architecture, source:Package, Maintainer,
		//         Origin, Section, Installed-Size, db-fsys:Last-Modified
		Name: "dpkg", Binary: "dpkg-query",
		VersionCmd: []string{"--version"},
		ListCmd: []string{"-W", "-f",
			"${Package}\t${Version}\t${Architecture}\t${source:Package}\t" +
				"${Maintainer}\t${Origin}\t${Section}\t${Installed-Size}\t" +
				"${db-fsys:Last-Modified}\n"},
		ParseLine: parseDpkgLine,
	},
	{
		// pacman: Arch Linux, Manjaro, EndeavourOS
		// -Qi (no args) dumps all packages in multi-line block format with rich metadata.
		Name: "pacman", Binary: "pacman",
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-Qi"},
		ParseBulk:  parsePacmanBulk,
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
// For apk, it prefers reading /lib/apk/db/installed directly for richer metadata.
func (d *SystemPkgDetector) ListPackages(ctx context.Context) []model.SystemPackage {
	if d.exec.GOOS() != model.PlatformLinux {
		return nil
	}

	for _, spec := range sysPkgSpecs {
		if _, err := d.exec.LookPath(spec.Binary); err != nil {
			continue
		}

		// For apk, prefer reading the installed DB directly — gives richer metadata
		// (maintainer, build time, commit hash) without spawning a subprocess.
		if spec.Name == "apk" {
			if pkgs := d.ListPackagesApkDB(ctx); len(pkgs) > 0 {
				return pkgs
			}
			// Fall through to command-line approach if DB read fails
		}

		stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 60*time.Second, spec.Binary, spec.ListCmd...)
		if err != nil || exitCode != 0 {
			return nil
		}

		if spec.ParseBulk != nil {
			return spec.ParseBulk(stdout)
		}
		return parsePackageList(stdout, spec.ParseLine)
	}

	return nil
}

// ListPackagesApkDB reads /lib/apk/db/installed directly for rich metadata.
// Falls back to the standard apk list --installed approach if the file is unreadable.
func (d *SystemPkgDetector) ListPackagesApkDB(ctx context.Context) []model.SystemPackage {
	data, err := d.exec.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return nil
	}
	return parseApkDB(string(data))
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

// ListSnapPackages returns installed snap packages with confinement and channel info.
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
		if len(fields) < 2 {
			continue
		}
		pkg := model.SystemPackage{
			Name:    fields[0],
			Version: fields[1],
		}
		// Rev is column 3 (index 2) — skip, low value
		// Tracking (channel) is column 4 (index 3)
		if len(fields) >= 4 {
			pkg.Channel = fields[3]
		}
		// Publisher is column 5 (index 4)
		if len(fields) >= 5 {
			pkg.Source = fields[4] // publisher name
		}
		// Notes is column 6 (index 5) — contains confinement info
		if len(fields) >= 6 {
			notes := fields[5]
			// Notes can be "-" (strict), "classic", "devmode", or combined flags
			switch {
			case strings.Contains(notes, "classic"):
				pkg.Confinement = "classic"
			case strings.Contains(notes, "devmode"):
				pkg.Confinement = "devmode"
			case notes == "-" || notes == "":
				pkg.Confinement = "strict"
			default:
				pkg.Confinement = "strict"
			}
		}
		packages = append(packages, pkg)
	}
	return packages
}

// ListFlatpakPackages returns installed flatpak applications with runtime and branch info.
func (d *SystemPkgDetector) ListFlatpakPackages(ctx context.Context) []model.SystemPackage {
	if _, err := d.exec.LookPath("flatpak"); err != nil {
		return nil
	}

	// Columns: application, name, version, arch, branch, origin, active, latest, runtime
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 30*time.Second,
		"flatpak", "list", "--app",
		"--columns=application,name,version,arch,branch,origin,active,latest,runtime")
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
		// Tab-separated: application\tname\tversion\tarch\tbranch\torigin\tactive\tlatest\truntime
		parts := strings.Split(line, "\t")
		if len(parts) == 0 || parts[0] == "" {
			continue
		}
		pkg := model.SystemPackage{Name: parts[0]}
		// Human-readable name (parts[1]) — we use app ID as Name for consistency;
		// the display name goes into Maintainer field if we want, but skip for now.
		if len(parts) >= 3 && parts[2] != "" {
			pkg.Version = parts[2]
		} else {
			pkg.Version = "unknown"
		}
		if len(parts) >= 4 {
			pkg.Arch = parts[3]
		}
		if len(parts) >= 5 {
			pkg.Channel = parts[4] // branch: "stable", "beta", etc.
		}
		if len(parts) >= 6 {
			pkg.Source = parts[5] // origin: "flathub", etc.
		}
		if len(parts) >= 7 && parts[6] != "" {
			pkg.CommitHash = parts[6] // active commit
		}
		// parts[7] = latest commit — compare with active to detect pending updates
		// We don't store separately; active commit is the one that matters.
		if len(parts) >= 9 && parts[8] != "" {
			pkg.Runtime = parts[8] // e.g. "org.freedesktop.Platform/x86_64/24.08"
		}
		packages = append(packages, pkg)
	}
	return packages
}

// ---------- Per-PM line parsers ----------

// parseRPMLine parses tab-separated RPM output with 13 fields:
// NAME\tVERSION-RELEASE\tARCH\tINSTALLTIME\tSOURCERPM\tVENDOR\tPACKAGER\tURL\tLICENSE\tBUILDTIME\tSIZE\tSIGPGP\tRSAHEADER
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
	if len(parts) >= 5 {
		pkg.Source = noneToEmpty(parts[4])
	}
	if len(parts) >= 6 {
		pkg.Vendor = noneToEmpty(parts[5])
	}
	if len(parts) >= 7 {
		pkg.Maintainer = noneToEmpty(parts[6])
	}
	if len(parts) >= 8 {
		pkg.URL = noneToEmpty(parts[7])
	}
	if len(parts) >= 9 {
		pkg.License = noneToEmpty(parts[8])
	}
	if len(parts) >= 10 {
		if ts, err := strconv.ParseInt(parts[9], 10, 64); err == nil {
			pkg.BuildTimeUnix = ts
		}
	}
	if len(parts) >= 11 {
		if sz, err := strconv.ParseInt(parts[10], 10, 64); err == nil {
			pkg.InstalledSize = sz
		}
	}
	// Signature: prefer SIGPGP, fall back to RSAHEADER
	if len(parts) >= 13 {
		sig := noneToEmpty(parts[11])
		if sig == "" {
			sig = noneToEmpty(parts[12])
		}
		pkg.Signature = sig
	}
	return pkg
}

// parseDpkgLine parses tab-separated dpkg-query output with 9 fields:
// Package\tVersion\tArchitecture\tsource:Package\tMaintainer\tOrigin\tSection\tInstalled-Size\tdb-fsys:Last-Modified
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
		pkg.Source = parts[3] // source:Package — always populated
	}
	if len(parts) >= 5 && parts[4] != "" {
		pkg.Maintainer = parts[4]
	}
	if len(parts) >= 6 && parts[5] != "" {
		pkg.Vendor = parts[5] // Origin: "Ubuntu", "Debian", etc.
	}
	// parts[6] = Section — a dpkg package category (for example "libs" or
	// "non-free/libs"), not a license expression, so map to Section field.
	if len(parts) >= 7 && parts[6] != "" {
		pkg.Section = parts[6]
	}
	if len(parts) >= 8 && parts[7] != "" {
		// Installed-Size in dpkg is in KB
		if sz, err := strconv.ParseInt(parts[7], 10, 64); err == nil {
			pkg.InstalledSize = sz * 1024 // convert to bytes for consistency with rpm
		}
	}
	if len(parts) >= 9 && parts[8] != "" {
		// db-fsys:Last-Modified is a unix timestamp — closest to install time for dpkg
		if ts, err := strconv.ParseInt(parts[8], 10, 64); err == nil {
			pkg.InstallTimeUnix = ts
		}
	}
	return pkg
}

// parsePacmanBulk parses the multi-line block output of `pacman -Qi`.
// Each package is a block of "Key : Value" lines separated by a blank line.
func parsePacmanBulk(stdout string) []model.SystemPackage {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil
	}

	var packages []model.SystemPackage
	// Split on double-newline to get per-package blocks
	blocks := strings.Split(stdout, "\n\n")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		pkg := parsePacmanBlock(block)
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
	}
	return packages
}

// parsePacmanBlock parses a single pacman -Qi block into a SystemPackage.
func parsePacmanBlock(block string) model.SystemPackage {
	pkg := model.SystemPackage{}
	for _, line := range strings.Split(block, "\n") {
		// Format: "Key                     : Value"
		idx := strings.Index(line, " : ")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+3:])
		if val == "None" || val == "" {
			continue
		}

		switch key {
		case "Name":
			pkg.Name = val
		case "Version":
			pkg.Version = val
		case "Architecture":
			pkg.Arch = val
		case "URL":
			pkg.URL = val
		case "Licenses":
			pkg.License = val
		case "Packager":
			pkg.Maintainer = val
		case "Build Date":
			pkg.BuildTimeUnix = parsePacmanDate(val)
		case "Install Date":
			pkg.InstallTimeUnix = parsePacmanDate(val)
		case "Install Reason":
			// "Explicitly installed" or "Installed as a dependency for another package"
			// Store shortened form in Vendor (repurposing for install-reason signal)
			// Actually, better to not overload Vendor. Skip for now — the field
			// doesn't map cleanly to our model and is lower priority.
		case "Installed Size":
			pkg.InstalledSize = parsePacmanSize(val)
		case "Validated By":
			pkg.Signature = val // e.g. "Signature" or "None"
		}
	}
	return pkg
}

// parsePacmanDate parses pacman's locale-dependent date strings.
// Common formats: "Sat 26 Apr 2025 10:30:00 PM UTC", "2025-04-26T22:30:00+0000"
func parsePacmanDate(s string) int64 {
	// Try common pacman date formats
	formats := []string{
		"Mon 02 Jan 2006 03:04:05 PM MST",
		"2006-01-02T15:04:05-0700",
		"2006-01-02 15:04:05",
		time.RFC1123Z,
		time.RFC1123,
		time.UnixDate,
	}
	for _, fmt := range formats {
		if t, err := time.Parse(fmt, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// parsePacmanSize parses "123.45 KiB" / "1.23 MiB" / "45.6 GiB" to bytes.
func parsePacmanSize(s string) int64 {
	parts := strings.Fields(s)
	if len(parts) != 2 {
		return 0
	}
	val, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		return 0
	}
	switch parts[1] {
	case "B":
		return int64(val)
	case "KiB":
		return int64(val * 1024)
	case "MiB":
		return int64(val * 1024 * 1024)
	case "GiB":
		return int64(val * 1024 * 1024 * 1024)
	}
	return 0
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

	// Extract license (field in parentheses: (license))
	for _, f := range fields {
		if strings.HasPrefix(f, "(") && strings.HasSuffix(f, ")") {
			pkg.License = f[1 : len(f)-1]
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

// parseApkDB parses /lib/apk/db/installed — the APKINDEX-format database file.
// Each package is a block of "X:value" lines separated by blank lines.
func parseApkDB(data string) []model.SystemPackage {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil
	}

	var packages []model.SystemPackage
	blocks := strings.Split(data, "\n\n")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		pkg := parseApkDBBlock(block)
		if pkg.Name != "" {
			packages = append(packages, pkg)
		}
	}
	return packages
}

// parseApkDBBlock parses a single package block from /lib/apk/db/installed.
func parseApkDBBlock(block string) model.SystemPackage {
	pkg := model.SystemPackage{}
	for _, line := range strings.Split(block, "\n") {
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		code := line[0]
		val := line[2:]

		switch code {
		case 'P': // Package name
			pkg.Name = val
		case 'V': // Version
			pkg.Version = val
		case 'A': // Architecture
			pkg.Arch = val
		case 'U': // URL
			pkg.URL = val
		case 'L': // License
			pkg.License = val
		case 'o': // Origin (source package)
			pkg.Source = val
		case 'm': // Maintainer
			pkg.Maintainer = val
		case 't': // Build time (epoch)
			if ts, err := strconv.ParseInt(val, 10, 64); err == nil {
				pkg.BuildTimeUnix = ts
			}
		case 'c': // Commit hash
			pkg.CommitHash = val
		case 'I': // Installed size
			if sz, err := strconv.ParseInt(val, 10, 64); err == nil {
				pkg.InstalledSize = sz
			}
		}
	}
	return pkg
}

// noneToEmpty converts rpm's "(none)" sentinel to empty string.
func noneToEmpty(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}
