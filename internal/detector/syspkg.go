package detector

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
)

// Linux system package limits. The record budget is shared by every source of
// one upload, Nix included, and equals the backend's per-upload bound; the
// Flatpak bound matches the backend's installation-source bound.
const (
	maxSystemPackageRecords       = 50_000
	maxFlatpakSources             = 256
	maxApkDBBytes           int64 = 8 << 20
)

// Discovery roots and source of the single-database managers, and the two
// Flatpak installation roots.
const (
	sysPkgMachineDefault    = "machine-default"
	flatpakSystemRoot       = "system-installations"
	flatpakUserRoot         = "user-installation"
	sysPkgScopeMachine      = "machine"
	sysPkgScopeUser         = "user"
	sysPkgToolUnavailable   = "query tool unavailable"
	sysPkgUnparsedOutput    = "unparsed output"
	sysPkgRecordLimit       = "record limit reached"
	flatpakListColumns      = "--columns=application,name,version,arch,branch,origin,active,latest,runtime,installation"
	flatpakListColumnsCount = 10
)

// sysPkgSpec defines how to detect and query a system package manager.
type sysPkgSpec struct {
	Name       string   // display name: "rpm", "dpkg", "pacman", "apk"
	Binary     string   // binary to look for in PATH
	Markers    []string // database paths whose presence means the manager is installed
	VersionCmd []string // command + args to get version (e.g., ["--version"])
	ListCmd    []string // command + args to list installed packages
	Timeout    time.Duration
	CLocale    bool // run the list under LC_ALL=C: its output is localized
	// ParseLine parses one output line. keep=false drops a valid record that
	// is not installed; an empty Name is an unparsed line.
	ParseLine func(line string) (pkg model.SystemPackage, keep bool)
	// ParseBulk, when non-nil, replaces line-by-line parsing. It receives the
	// full stdout and returns all packages at once, plus the number of blocks it
	// could not parse. Used by pacman -Qi which outputs multi-line blocks rather
	// than one-package-per-line.
	ParseBulk func(stdout string) ([]model.SystemPackage, int)
}

var sysPkgSpecs = []sysPkgSpec{
	{
		// RPM: works on Fedora, RHEL, CentOS, SUSE, Amazon Linux
		// Fields: NAME, VERSION-RELEASE, ARCH, INSTALLTIME, SOURCERPM, VENDOR,
		//         PACKAGER, URL, LICENSE, BUILDTIME, SIZE, SIGPGP, RSAHEADER, EPOCH
		Name: "rpm", Binary: "rpm",
		Markers:    []string{"/usr/lib/sysimage/rpm", "/var/lib/rpm"},
		VersionCmd: []string{"--version"},
		ListCmd: []string{"-qa", "--queryformat",
			"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\t%{SOURCERPM}\t" +
				"%{VENDOR}\t%{PACKAGER}\t%{URL}\t%{LICENSE}\t%{BUILDTIME}\t%{SIZE}\t" +
				"%{SIGPGP:pgpsig}\t%{RSAHEADER:pgpsig}\t%{EPOCH}\n"},
		Timeout:   60 * time.Second,
		ParseLine: parseRPMLine,
	},
	{
		// dpkg: works on Debian, Ubuntu, Mint, Pop!_OS
		// Fields: Package, Version, Architecture, source:Package, Maintainer,
		//         Origin, Section, Installed-Size, db-fsys:Last-Modified, db:Status-Status
		Name: "dpkg", Binary: "dpkg-query",
		Markers:    []string{"/var/lib/dpkg/status"},
		VersionCmd: []string{"--version"},
		ListCmd: []string{"-W", "-f",
			"${Package}\t${Version}\t${Architecture}\t${source:Package}\t" +
				"${Maintainer}\t${Origin}\t${Section}\t${Installed-Size}\t" +
				"${db-fsys:Last-Modified}\t${db:Status-Status}\n"},
		Timeout:   60 * time.Second,
		ParseLine: parseDpkgLine,
	},
	{
		// pacman: Arch Linux, Manjaro, EndeavourOS
		// -Qi (no args) dumps all packages in multi-line block format with rich
		// metadata. Its field names and dates follow the locale.
		Name: "pacman", Binary: "pacman",
		Markers:    []string{"/var/lib/pacman/local"},
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"-Qi"},
		Timeout:    60 * time.Second,
		CLocale:    true,
		ParseBulk:  parsePacmanBulk,
	},
	{
		// apk: Alpine Linux
		// Format: "name-version arch {origin} (license)"
		Name: "apk", Binary: "apk",
		Markers:    []string{"/lib/apk/db/installed", "/usr/lib/apk/db/installed"},
		VersionCmd: []string{"--version"},
		ListCmd:    []string{"list", "--installed"},
		Timeout:    60 * time.Second,
		ParseLine:  parseApkLineRich,
	},
	{
		// snap: current instances only. Columns: Name Version Rev Tracking Publisher Notes
		Name: "snap", Binary: "snap",
		Markers:    []string{"/var/lib/snapd"},
		VersionCmd: []string{"version"},
		ListCmd:    []string{"list"},
		Timeout:    30 * time.Second,
		ParseBulk:  parseSnapList,
	},
}

// SystemPkgDetector detects installed system packages on Linux.
type SystemPkgDetector struct {
	exec executor.Executor
	log  *progress.Logger
}

func NewSystemPkgDetector(exec executor.Executor, log *progress.Logger) *SystemPkgDetector {
	if log == nil {
		log = progress.NewNoop()
	}
	return &SystemPkgDetector{exec: exec, log: log}
}

// sysPkgRun collects the sources of one scan against the shared record budget.
type sysPkgRun struct {
	scans   []model.SystemPackageScanResult
	roots   []model.SystemPackageDiscoveryRoot
	budget  int
	cut     bool
	flatpak *model.PkgManager // set when the binary is present, even with no apps
}

// emit appends a source, keeping at most the remaining record budget. The
// source that does not fit becomes partial and nothing after it is emitted.
// It reports whether the source was emitted whole.
func (r *sysPkgRun) emit(res model.SystemPackageScanResult) bool {
	if r.cut {
		return false
	}
	if len(res.Packages) > r.budget {
		res.Packages = res.Packages[:r.budget]
		res.PackagesCount = len(res.Packages)
		res.Status, res.Error = model.SystemPackageStatusPartial, sysPkgRecordLimit
		r.cut = true
	}
	r.budget -= len(res.Packages)
	r.scans = append(r.scans, res)
	return !r.cut
}

func newSysPkgRun() *sysPkgRun {
	return &sysPkgRun{budget: maxSystemPackageRecords}
}

// addRoot lists a root. After a budget cut nothing more is listed: a source
// that was not emitted must not be retired by omission.
func (r *sysPkgRun) addRoot(scanType, scope, path string) {
	if r.cut {
		return
	}
	r.roots = append(r.roots, model.SystemPackageDiscoveryRoot{ScanType: scanType, Scope: scope, Path: path})
}

// ScanSystemPackages runs the Linux managers on userExec, then the Nix reader
// on the raw exec, against one record budget. Nix needs the raw executor:
// UserAwareExecutor.Getenv sources a login shell. The inventory lists the
// discovery roots whose sources were fully enumerated.
func ScanSystemPackages(ctx context.Context, userExec, exec executor.Executor, log *progress.Logger,
	target *user.User, includeNetworkVolumes *bool) ([]model.SystemPackageScanResult, *model.SystemPackageInventory) {
	r := newSysPkgRun()
	NewSystemPkgDetector(userExec, log).scan(ctx, r)
	newNixScanner(exec, log).scan(ctx, r, target, includeNetworkVolumes)
	return r.scans, &model.SystemPackageInventory{
		SchemaVersion:  model.SystemPackageInventorySchemaVersion,
		DiscoveryRoots: append([]model.SystemPackageDiscoveryRoot{}, r.roots...),
	}
}

// Scan collects the Linux managers alone, as community mode reports them.
// flatpak is the Flatpak manager when its binary is present: an installation
// with no apps emits no scan.
func (d *SystemPkgDetector) Scan(ctx context.Context) (scans []model.SystemPackageScanResult, flatpak *model.PkgManager) {
	r := newSysPkgRun()
	d.scan(ctx, r)
	return r.scans, r.flatpak
}

// scan collects every present manager independently, then Flatpak, so one
// broken or empty manager cannot mask another.
func (d *SystemPkgDetector) scan(ctx context.Context, r *sysPkgRun) {
	if d.exec.GOOS() != model.PlatformLinux {
		return
	}
	for _, spec := range sysPkgSpecs {
		d.scanManager(ctx, r, spec)
	}
	d.scanFlatpak(ctx, r)
}

// markerState stats each marker: present when any exists, absent only when
// every one is definitively missing. Any other error leaves presence unknown.
func (d *SystemPkgDetector) markerState(markers []string) (present, absent bool) {
	absent = true
	for _, m := range markers {
		_, err := d.exec.Stat(m)
		switch {
		case err == nil:
			return true, false
		case !errors.Is(err, fs.ErrNotExist):
			absent = false
		}
	}
	return false, absent
}

// managerInfo is optional metadata: a failed version probe leaves "unknown"
// and never changes the source status.
func (d *SystemPkgDetector) managerInfo(ctx context.Context, name, binary, path string, versionCmd []string) *model.PkgManager {
	version := "unknown"
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 10*time.Second, binary, versionCmd...)
	if err == nil && exitCode == 0 {
		if line := strings.TrimSpace(strings.SplitN(stdout, "\n", 2)[0]); line != "" {
			version = line
		}
	}
	return &model.PkgManager{Name: name, Version: version, Path: path}
}

// sysPkgResult builds one source with its status. Packages carry the source scope.
func sysPkgResult(scanType string, pm *model.PkgManager, pkgs []model.SystemPackage, start time.Time,
	sourceID, root, scope, status, errText string) model.SystemPackageScanResult {
	for i := range pkgs {
		pkgs[i].Scope = scope
	}
	res := scanResult(scanType, pm, pkgs, start)
	res.SourceID, res.DiscoveryRoot, res.Scope, res.Status, res.Error = sourceID, root, scope, status, errText
	return res
}

func sysPkgQueryError(exitCode int) string {
	if exitCode == 124 {
		return "timed out"
	}
	return fmt.Sprintf("query failed (exit %d)", exitCode)
}

// scanManager decides presence from the binary and the database markers, then
// queries the manager. A marker without its binary is a failed source; the
// root is listed only when presence was decided.
func (d *SystemPkgDetector) scanManager(ctx context.Context, r *sysPkgRun, spec sysPkgSpec) {
	if r.cut {
		return
	}
	start := time.Now()
	present, absent := d.markerState(spec.Markers)
	path, lookErr := d.exec.LookPath(spec.Binary)
	var pm *model.PkgManager
	var pkgs []model.SystemPackage
	var status, errText string
	switch {
	case lookErr == nil:
		pm = d.managerInfo(ctx, spec.Name, spec.Binary, path, spec.VersionCmd)
		pkgs, status, errText = d.listPackages(ctx, spec)
	case present:
		status, errText = model.SystemPackageStatusFailed, sysPkgToolUnavailable
	case absent:
		r.addRoot(spec.Name, sysPkgScopeMachine, sysPkgMachineDefault)
		return
	default:
		d.log.Debug("%s: database marker unreadable, presence unknown", spec.Name)
		return
	}
	if r.emit(sysPkgResult(spec.Name, pm, pkgs, start, sysPkgMachineDefault, sysPkgMachineDefault,
		sysPkgScopeMachine, status, errText)) {
		r.addRoot(spec.Name, sysPkgScopeMachine, sysPkgMachineDefault)
	}
}

// listPackages returns the packages and the source status. The exit status is
// checked before output is read; an unparsed record keeps the valid rows and
// makes the source partial.
func (d *SystemPkgDetector) listPackages(ctx context.Context, spec sysPkgSpec) ([]model.SystemPackage, string, string) {
	// For apk, prefer reading the installed DB directly: it gives richer metadata
	// (maintainer, build time, commit hash) without spawning a subprocess.
	if spec.Name == "apk" {
		if pkgs, unparsed, ok := d.readApkDB(spec.Markers); ok {
			status, errText := parseStatus(spec.Name, unparsed, d.log)
			return pkgs, status, errText
		}
	}

	name, args := spec.Binary, spec.ListCmd
	if spec.CLocale {
		name, args = "env", append([]string{"LC_ALL=C", spec.Binary}, spec.ListCmd...)
	}
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, spec.Timeout, name, args...)
	if err != nil || exitCode != 0 {
		return nil, model.SystemPackageStatusFailed, sysPkgQueryError(exitCode)
	}
	var pkgs []model.SystemPackage
	var unparsed int
	if spec.ParseBulk != nil {
		pkgs, unparsed = spec.ParseBulk(stdout)
	} else {
		pkgs, unparsed = parsePackageList(stdout, spec.ParseLine)
	}
	status, errText := parseStatus(spec.Name, unparsed, d.log)
	return pkgs, status, errText
}

// parseStatus logs the count of unparsed records, never their content.
func parseStatus(source string, unparsed int, log *progress.Logger) (string, string) {
	if unparsed == 0 {
		return model.SystemPackageStatusComplete, ""
	}
	log.Warn("%s: %d records could not be parsed; results may be incomplete", source, unparsed)
	return model.SystemPackageStatusPartial, sysPkgUnparsedOutput
}

// readApkDB reads the installed database through a bounded read. ok=false
// sends the caller to the command fallback: a read error, or content that is
// not the text format this parser reads.
func (d *SystemPkgDetector) readApkDB(markers []string) (pkgs []model.SystemPackage, unparsed int, ok bool) {
	roots := make([]string, len(markers))
	for i, m := range markers {
		roots[i] = filepath.Dir(m)
	}
	files := d.exec.GuardedFiles(roots, nil, maxApkDBBytes)
	for _, m := range markers {
		data, err := files.ReadFile(m)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
			d.log.Debug("apk: installed database unreadable or not text, using apk list")
			return nil, 0, false
		}
		pkgs, unparsed = parseApkDB(string(data))
		return pkgs, unparsed, true
	}
	return nil, 0, false
}

func parsePackageList(stdout string, parseLine func(string) (model.SystemPackage, bool)) ([]model.SystemPackage, int) {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil, 0
	}

	var packages []model.SystemPackage
	unparsed := 0
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pkg, keep := parseLine(line)
		switch {
		case !keep:
		case pkg.Name == "":
			unparsed++
		default:
			packages = append(packages, pkg)
		}
	}
	return packages, unparsed
}

// parseSnapList parses `snap list` output, current installs only.
func parseSnapList(stdout string) ([]model.SystemPackage, int) {
	// snap list output: "Name  Version  Rev  Tracking  Publisher  Notes"
	// Skip the header line
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) < 2 {
		return nil, 0
	}

	var packages []model.SystemPackage
	unparsed := 0
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			unparsed++
			continue
		}
		pkg := model.SystemPackage{
			Name:        fields[0],
			Version:     fields[1],
			InstallPath: "/snap/" + fields[0] + "/current",
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
			default:
				pkg.Confinement = "strict"
			}
		}
		packages = append(packages, pkg)
	}
	return packages, unparsed
}

// flatpakRow is one parsed `flatpak list` row: the app ID is pkg.Name, the
// arch pkg.Arch and the branch pkg.Channel.
type flatpakRow struct {
	pkg          model.SystemPackage
	installation string
}

// flatpakInstallation groups the rows of one installation.
type flatpakInstallation struct {
	column   string // the native installation column: user, system, system (<id>)
	selector string // the flag that selects it again
	user     bool
	rows     []flatpakRow
}

// flatpakListArgs runs flatpak with stderr folded into stdout. flatpak list
// skips a deployment it cannot read with only a warning on stderr and still
// exits 0, and the user-aware executor drops stderr on success, so the merged
// stream is how that warning reaches the parser on both executors. The script
// is constant; every variable value is a positional argument.
func flatpakListArgs(selector ...string) []string {
	args := []string{"-c", `exec "$@" 2>&1`, "sh", "flatpak", "list"}
	args = append(args, selector...)
	return append(args, "--app", flatpakListColumns)
}

// runFlatpakList returns the rows and the number of unparsed lines, or the
// query error when the command failed.
func (d *SystemPkgDetector) runFlatpakList(ctx context.Context, selector ...string) (rows []flatpakRow, unparsed int, errText string) {
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 30*time.Second, "/bin/sh", flatpakListArgs(selector...)...)
	if err != nil || exitCode != 0 {
		return nil, 0, sysPkgQueryError(exitCode)
	}
	rows, unparsed = parseFlatpakList(stdout)
	return rows, unparsed, ""
}

// parseFlatpakList parses the tab-separated columns in flatpakListColumns. Any
// other line, such as a merged warning, is counted as unparsed.
func parseFlatpakList(stdout string) ([]flatpakRow, int) {
	var rows []flatpakRow
	unparsed := 0
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != flatpakListColumnsCount || parts[0] == "" || parts[3] == "" || parts[4] == "" || parts[9] == "" {
			unparsed++
			continue
		}
		// parts[1] is the human-readable name; the app ID stays the Name.
		// parts[7] is the latest commit; the active commit is the one installed.
		pkg := model.SystemPackage{
			Name: parts[0], Version: parts[2], Arch: parts[3],
			Channel: parts[4], Source: parts[5], CommitHash: parts[6], Runtime: parts[8],
		}
		if pkg.Version == "" {
			pkg.Version = "unknown"
		}
		rows = append(rows, flatpakRow{pkg: pkg, installation: parts[9]})
	}
	return rows, unparsed
}

// flatpakSelector maps the native installation column to the flag that
// selects that installation: "user", "system" or "system (<id>)".
func flatpakSelector(column string) (selector string, user, ok bool) {
	switch {
	case column == "user":
		return "--user", true, true
	case column == "system":
		return "--system", false, true
	case strings.HasPrefix(column, "system (") && strings.HasSuffix(column, ")"):
		id := strings.TrimSuffix(strings.TrimPrefix(column, "system ("), ")")
		if id == "" || strings.ContainsAny(id, " \t") {
			return "", false, false
		}
		return "--installation=" + id, false, true
	}
	return "", false, false
}

// groupFlatpak groups rows by installation in a fixed order: user, the default
// system installation, then configured ones by ID. A row whose column cannot
// be mapped is reported as unmapped.
func groupFlatpak(rows []flatpakRow) (insts []*flatpakInstallation, unmapped int) {
	byColumn := map[string]*flatpakInstallation{}
	for _, row := range rows {
		inst := byColumn[row.installation]
		if inst == nil {
			sel, user, ok := flatpakSelector(row.installation)
			if !ok {
				unmapped++
				continue
			}
			inst = &flatpakInstallation{column: row.installation, selector: sel, user: user}
			byColumn[row.installation] = inst
			insts = append(insts, inst)
		}
		inst.rows = append(inst.rows, row)
	}
	rank := func(i *flatpakInstallation) int {
		switch i.column {
		case "user":
			return 0
		case "system":
			return 1
		}
		return 2
	}
	slices.SortFunc(insts, func(a, b *flatpakInstallation) int {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(a.column, b.column)
	})
	return insts, unmapped
}

// flatpakUserDir mirrors Flatpak's own user installation resolver:
// FLATPAK_USER_DIR, else <XDG data dir>/flatpak. "" when the user environment
// could not be read or a value is not absolute.
func (d *SystemPkgDetector) flatpakUserDir() string {
	if executor.UserEnvironmentError(d.exec) != nil {
		return ""
	}
	if dir := d.exec.Getenv("FLATPAK_USER_DIR"); dir != "" {
		if filepath.IsAbs(dir) {
			return filepath.Clean(dir)
		}
		return ""
	}
	if data := d.exec.Getenv("XDG_DATA_HOME"); data != "" {
		if filepath.IsAbs(data) {
			return filepath.Join(data, "flatpak")
		}
		return ""
	}
	if u, err := d.exec.LoggedInUser(); err == nil && filepath.IsAbs(u.HomeDir) {
		return filepath.Join(u.HomeDir, ".local", "share", "flatpak")
	}
	return ""
}

// flatpakLocation asks the installation for the deploy directory of one of its
// rows and strips /app/<id>/<arch>/<branch>/<commit>. The suffix must match
// that row, or the installation stays unmapped.
func (d *SystemPkgDetector) flatpakLocation(ctx context.Context, inst *flatpakInstallation) string {
	row := inst.rows[0].pkg
	stdout, _, exitCode, err := d.exec.RunWithTimeout(ctx, 10*time.Second, "flatpak", "info", inst.selector,
		"--show-location", "--arch="+row.Arch, row.Name, row.Channel)
	if err != nil || exitCode != 0 {
		return ""
	}
	deploy := strings.TrimSpace(stdout)
	suffix := "/app/" + row.Name + "/" + row.Arch + "/" + row.Channel + "/"
	i := strings.LastIndex(deploy, suffix)
	if i <= 0 {
		return ""
	}
	commit := deploy[i+len(suffix):]
	base := deploy[:i]
	if commit == "" || strings.Contains(commit, "/") || !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return ""
	}
	return base
}

// scanFlatpak reports one source per installation that has apps, keyed by the
// installation path Flatpak itself uses. The roots are listed only when the
// global list enumerated every installation and printed nothing it could not
// parse: a deployment Flatpak cannot read is skipped with only a warning, and
// the missing row's installation is unknown.
func (d *SystemPkgDetector) scanFlatpak(ctx context.Context, r *sysPkgRun) {
	if r.cut {
		return
	}
	start := time.Now()
	userDir := d.flatpakUserDir()
	path, lookErr := d.exec.LookPath("flatpak")
	if lookErr != nil {
		d.flatpakWithoutBinary(r, userDir, start)
		return
	}
	pm := d.managerInfo(ctx, "flatpak", "flatpak", path, []string{"--version"})
	r.flatpak = pm

	rows, unparsed, errText := d.runFlatpakList(ctx)
	if errText != "" {
		d.flatpakFallback(ctx, r, pm, userDir, start)
		return
	}
	insts, unmapped := groupFlatpak(rows)
	status, errText := parseStatus("flatpak", unparsed, d.log)
	complete := status == model.SystemPackageStatusComplete
	if unmapped > 0 {
		d.log.Warn("flatpak: %d rows name an unknown installation; results may be incomplete", unmapped)
	}
	systemListable := complete && unmapped == 0
	if len(insts) > maxFlatpakSources {
		insts, systemListable = insts[:maxFlatpakSources], false
	}
	userListable := complete
	sawUser := false
	for _, inst := range insts {
		sawUser = sawUser || inst.user
		if !d.emitFlatpak(ctx, r, pm, inst, userDir, status, errText, start) {
			if inst.user {
				userListable = false
			} else {
				systemListable = false
			}
		}
	}
	if !sawUser && userDir == "" {
		// No user rows to retire against an unknown user installation path.
		userListable = false
	}
	if userListable {
		r.addRoot("flatpak", sysPkgScopeUser, flatpakUserRoot)
	}
	if systemListable {
		r.addRoot("flatpak", sysPkgScopeMachine, flatpakSystemRoot)
	}
}

// emitFlatpak maps one installation to its path and emits its source. It
// reports whether the source was emitted whole and complete.
func (d *SystemPkgDetector) emitFlatpak(ctx context.Context, r *sysPkgRun, pm *model.PkgManager,
	inst *flatpakInstallation, userDir, status, errText string, start time.Time) bool {
	base := ""
	if inst.user {
		base = userDir
	}
	if base == "" {
		base = d.flatpakLocation(ctx, inst)
	}
	if base == "" {
		d.log.Warn("flatpak: location of installation %q unavailable; its apps are not reported", inst.column)
		return false
	}
	scope, root := sysPkgScopeMachine, flatpakSystemRoot
	if inst.user {
		scope, root = sysPkgScopeUser, flatpakUserRoot
	}
	pkgs := make([]model.SystemPackage, 0, len(inst.rows))
	for _, row := range inst.rows {
		pkg := row.pkg
		pkg.InstallPath = base + "/app/" + pkg.Name + "/" + pkg.Arch + "/" + pkg.Channel + "/active"
		pkgs = append(pkgs, pkg)
	}
	return r.emit(sysPkgResult("flatpak", pm, pkgs, start, base, root, scope, status, errText)) &&
		status == model.SystemPackageStatusComplete
}

// flatpakFallback isolates installations after the global list failed: the
// user and default system installations are listed separately. Configured
// installations are unknown, so the system root is never listed here.
func (d *SystemPkgDetector) flatpakFallback(ctx context.Context, r *sysPkgRun, pm *model.PkgManager, userDir string, start time.Time) {
	for _, sel := range []string{"--user", "--system"} {
		user := sel == "--user"
		rows, unparsed, errText := d.runFlatpakList(ctx, sel)
		if errText != "" {
			if user && userDir != "" {
				r.emit(sysPkgResult("flatpak", pm, nil, start, userDir, flatpakUserRoot, sysPkgScopeUser,
					model.SystemPackageStatusFailed, errText))
			}
			continue
		}
		column := strings.TrimPrefix(sel, "--")
		inst := &flatpakInstallation{column: column, selector: sel, user: user}
		for _, row := range rows {
			if row.installation == column {
				inst.rows = append(inst.rows, row)
			} else {
				unparsed++
			}
		}
		status, errText := parseStatus("flatpak", unparsed, d.log)
		if len(inst.rows) == 0 {
			if user && unparsed == 0 && userDir != "" {
				r.addRoot("flatpak", sysPkgScopeUser, flatpakUserRoot)
			}
			continue
		}
		if d.emitFlatpak(ctx, r, pm, inst, userDir, status, errText, start) && user {
			r.addRoot("flatpak", sysPkgScopeUser, flatpakUserRoot)
		}
	}
}

// flatpakWithoutBinary handles a missing flatpak command. A default
// installation directory present without the command is a failed source. A
// root is listed only when nothing of it can exist: the user directory absent,
// or the default system directory and the configured-installation directory
// both absent.
func (d *SystemPkgDetector) flatpakWithoutBinary(r *sysPkgRun, userDir string, start time.Time) {
	if userDir != "" {
		present, absent := d.markerState([]string{userDir})
		switch {
		case present:
			r.emit(sysPkgResult("flatpak", nil, nil, start, userDir, flatpakUserRoot, sysPkgScopeUser,
				model.SystemPackageStatusFailed, sysPkgToolUnavailable))
		case absent:
			r.addRoot("flatpak", sysPkgScopeUser, flatpakUserRoot)
		}
	}
	const systemDir = "/var/lib/flatpak"
	if present, _ := d.markerState([]string{systemDir}); present {
		r.emit(sysPkgResult("flatpak", nil, nil, start, systemDir, flatpakSystemRoot, sysPkgScopeMachine,
			model.SystemPackageStatusFailed, sysPkgToolUnavailable))
		return
	}
	if _, absent := d.markerState([]string{systemDir, "/etc/flatpak/installations.d"}); absent {
		r.addRoot("flatpak", sysPkgScopeMachine, flatpakSystemRoot)
	}
}

// ---------- Per-PM line parsers ----------

// parseRPMLine parses tab-separated RPM output with 14 fields:
// NAME\tVERSION-RELEASE\tARCH\tINSTALLTIME\tSOURCERPM\tVENDOR\tPACKAGER\tURL\tLICENSE\tBUILDTIME\tSIZE\tSIGPGP\tRSAHEADER\tEPOCH
// Any other field count, or an epoch that is not a number, is unparsed.
func parseRPMLine(line string) (model.SystemPackage, bool) {
	parts := strings.Split(line, "\t")
	pkg := model.SystemPackage{}
	if len(parts) != 14 {
		return pkg, true
	}
	if epoch := noneToEmpty(parts[13]); epoch != "" {
		n, err := strconv.Atoi(epoch)
		if err != nil || n < 0 {
			return pkg, true
		}
		pkg.Epoch = n
	}
	pkg.Name, pkg.Version, pkg.Arch = parts[0], parts[1], parts[2]
	if ts, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
		pkg.InstallTimeUnix = ts
	}
	pkg.Source = noneToEmpty(parts[4])
	pkg.Vendor = noneToEmpty(parts[5])
	pkg.Maintainer = noneToEmpty(parts[6])
	pkg.URL = noneToEmpty(parts[7])
	pkg.License = noneToEmpty(parts[8])
	if ts, err := strconv.ParseInt(parts[9], 10, 64); err == nil {
		pkg.BuildTimeUnix = ts
	}
	if sz, err := strconv.ParseInt(parts[10], 10, 64); err == nil {
		pkg.InstalledSize = sz
	}
	// Signature: prefer SIGPGP, fall back to RSAHEADER
	pkg.Signature = noneToEmpty(parts[11])
	if pkg.Signature == "" {
		pkg.Signature = noneToEmpty(parts[12])
	}
	return pkg, true
}

// parseDpkgLine parses tab-separated dpkg-query output with 10 fields:
// Package\tVersion\tArchitecture\tsource:Package\tMaintainer\tOrigin\tSection\tInstalled-Size\tdb-fsys:Last-Modified\tdb:Status-Status
// A package removed with its configuration kept ("config-files") or only
// known to the database ("not-installed") is not installed and is dropped;
// the transitional states are still on disk and are kept.
func parseDpkgLine(line string) (model.SystemPackage, bool) {
	parts := strings.Split(line, "\t")
	pkg := model.SystemPackage{}
	if len(parts) != 10 {
		return pkg, true
	}
	if s := parts[9]; s == "config-files" || s == "not-installed" {
		return pkg, false
	}
	// Source is source:Package, always populated; Vendor is Origin ("Ubuntu",
	// "Debian"); Section is a package category such as "libs", not a license.
	pkg.Name, pkg.Version, pkg.Arch = parts[0], parts[1], parts[2]
	pkg.Source, pkg.Maintainer, pkg.Vendor, pkg.Section = parts[3], parts[4], parts[5], parts[6]
	// Installed-Size is in KiB; bytes match rpm.
	if sz, err := strconv.ParseInt(parts[7], 10, 64); err == nil {
		pkg.InstalledSize = sz * 1024
	}
	// db-fsys:Last-Modified is the closest dpkg has to an install time.
	if ts, err := strconv.ParseInt(parts[8], 10, 64); err == nil {
		pkg.InstallTimeUnix = ts
	}
	return pkg, true
}

// parsePacmanBulk parses the multi-line block output of `pacman -Qi`.
// Each package is a block of "Key : Value" lines separated by a blank line.
// A block without a name is counted as unparsed.
func parsePacmanBulk(stdout string) ([]model.SystemPackage, int) {
	stdout = strings.TrimSpace(stdout)
	if stdout == "" {
		return nil, 0
	}

	var packages []model.SystemPackage
	unparsed := 0
	// Split on double-newline to get per-package blocks
	blocks := strings.Split(stdout, "\n\n")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		pkg := parsePacmanBlock(block)
		if pkg.Name == "" {
			unparsed++
			continue
		}
		packages = append(packages, pkg)
	}
	return packages, unparsed
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
// Common formats: "Sat 26 Apr 2025 10:30:00 PM UTC", "2025-04-26T22:30:00+0000",
// and "Sat Apr 26 22:30:00 2025" under LC_ALL=C.
func parsePacmanDate(s string) int64 {
	// Try common pacman date formats
	formats := []string{
		time.ANSIC,
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
func parseApkLineRich(line string) (model.SystemPackage, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return model.SystemPackage{}, true
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
		return pkg, true
	}
	rest := nameVer[lastDash+1:]
	if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		pkg.Name = nameVer[:lastDash]
		pkg.Version = rest
		return pkg, true
	}
	secondDash := strings.LastIndex(nameVer[:lastDash], "-")
	if secondDash > 0 {
		pkg.Name = nameVer[:secondDash]
		pkg.Version = nameVer[secondDash+1:]
		return pkg, true
	}
	pkg.Name = nameVer
	pkg.Version = "unknown"
	return pkg, true
}

// parseApkDB parses /lib/apk/db/installed — the APKINDEX-format database file.
// Each package is a block of "X:value" lines separated by blank lines. A
// block without a name is counted as unparsed.
func parseApkDB(data string) ([]model.SystemPackage, int) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, 0
	}

	var packages []model.SystemPackage
	unparsed := 0
	blocks := strings.Split(data, "\n\n")
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		pkg := parseApkDBBlock(block)
		if pkg.Name == "" {
			unparsed++
			continue
		}
		packages = append(packages, pkg)
	}
	return packages, unparsed
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
