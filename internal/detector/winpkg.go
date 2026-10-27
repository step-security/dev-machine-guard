package detector

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// arpEntry is one subkey of an Uninstall registry key ("Programs and Features").
type arpEntry struct {
	KeyName          string
	Hive             string // HKLM or HKCU
	View             string // 64 or 32 (HKLM only)
	DisplayName      string
	DisplayVersion   string
	Publisher        string
	InstallLocation  string
	InstallDate      string // YYYYMMDD
	URLInfoAbout     string
	EstimatedSizeKB  uint32 // REG_DWORD
	SystemComponent  bool
	WindowsInstaller bool
	ParentKeyName    string
	ReleaseType      string
}

// WindowsPkgDetector inventories Windows software from the Uninstall
// registry keys (ARP), Chocolatey, Scoop and winget portable packages. It
// only reads the registry and files — winget/choco/scoop are never run
// (winget is a per-user MSIX that is unreliable outside an interactive shell;
// Win32_Product triggers MSI repairs).
type WindowsPkgDetector struct {
	exec executor.Executor
}

func NewWindowsPkgDetector(exec executor.Executor) *WindowsPkgDetector {
	return &WindowsPkgDetector{exec: exec}
}

// Scan returns one result per source that is present. ARP always reports.
func (d *WindowsPkgDetector) Scan(ctx context.Context) []model.SystemPackageScanResult {
	if d.exec.GOOS() != model.PlatformWindows {
		return nil
	}
	var results []model.SystemPackageScanResult

	start := time.Now()
	entries := readARPEntries(ctx, d.exec)
	arp := arpPackages(entries)
	results = append(results, scanResult("arp", &model.PkgManager{Name: "arp", Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`}, arp, start))

	home := ""
	if u, err := d.exec.LoggedInUser(); err == nil {
		home = u.HomeDir
	}
	programData := firstNonEmptyStr(d.exec.Getenv("ProgramData"), `C:\ProgramData`)

	chocoRoot := firstNonEmptyStr(d.exec.Getenv("ChocolateyInstall"), filepath.Join(programData, "chocolatey"))
	if d.exec.DirExists(filepath.Join(chocoRoot, "lib")) {
		start = time.Now()
		pkgs := d.chocoPackages(chocoRoot)
		results = append(results, scanResult("choco", &model.PkgManager{Name: "choco", Path: chocoRoot}, pkgs, start))
	}

	var scoopPkgs []model.SystemPackage
	var scoopPaths []string
	start = time.Now()
	for _, r := range []struct{ root, scope string }{
		{firstNonEmptyStr(d.exec.Getenv("SCOOP"), joinIf(home, "scoop")), "user"},
		{firstNonEmptyStr(d.exec.Getenv("SCOOP_GLOBAL"), filepath.Join(programData, "scoop")), "machine"},
	} {
		if r.root == "" || !d.exec.DirExists(filepath.Join(r.root, "apps")) {
			continue
		}
		scoopPaths = append(scoopPaths, r.root)
		scoopPkgs = append(scoopPkgs, d.scoopPackages(r.root, r.scope)...)
	}
	if len(scoopPaths) > 0 {
		results = append(results, scanResult("scoop", &model.PkgManager{Name: "scoop", Path: strings.Join(scoopPaths, ";")}, scoopPkgs, start))
	}

	var wingetPkgs []model.SystemPackage
	var wingetPaths []string
	start = time.Now()
	// winget registers a portable package's ARP entry in the hive of its
	// scope; keep them apart so a user install can't shadow a machine one.
	arpByScope := map[string]map[string]arpEntry{"user": {}, "machine": {}}
	for _, e := range entries {
		scope := "machine"
		if e.Hive == "HKCU" {
			scope = "user"
		}
		arpByScope[scope][strings.ToLower(e.KeyName)] = e
	}
	for _, r := range []struct{ root, scope string }{
		{joinIf(d.exec.Getenv("LOCALAPPDATA"), "Microsoft", "WinGet", "Packages"), "user"},
		{joinIf(d.exec.Getenv("ProgramFiles"), "WinGet", "Packages"), "machine"},
	} {
		if r.root == "" || !d.exec.DirExists(r.root) {
			continue
		}
		wingetPaths = append(wingetPaths, r.root)
		wingetPkgs = append(wingetPkgs, d.wingetPortablePackages(r.root, r.scope, arpByScope[r.scope])...)
	}
	if len(wingetPaths) > 0 {
		results = append(results, scanResult("winget", &model.PkgManager{Name: "winget", Path: strings.Join(wingetPaths, ";")}, wingetPkgs, start))
	}
	return results
}

func scanResult(scanType string, pm *model.PkgManager, pkgs []model.SystemPackage, start time.Time) model.SystemPackageScanResult {
	if pkgs == nil {
		pkgs = []model.SystemPackage{}
	}
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	return model.SystemPackageScanResult{
		ScanType:       scanType,
		PackageManager: pm,
		Packages:       pkgs,
		PackagesCount:  len(pkgs),
		ScanDurationMs: time.Since(start).Milliseconds(),
	}
}

// arpPackages filters ARP entries the way Programs and Features does —
// no DisplayName, SystemComponent=1, and updates/hotfixes (ParentKeyName or
// an update ReleaseType) are hidden — and dedupes entries visible from more
// than one registry view.
func arpPackages(entries []arpEntry) []model.SystemPackage {
	seen := map[string]bool{}
	var out []model.SystemPackage
	for _, e := range entries {
		if strings.TrimSpace(e.DisplayName) == "" || e.SystemComponent || e.ParentKeyName != "" {
			continue
		}
		switch strings.ToLower(e.ReleaseType) {
		case "update", "hotfix", "security update", "update rollup", "service pack":
			continue
		}
		// Same labels can be separate installs (x86 and x64 copies in
		// different dirs): keep the registry view and install location in
		// the identity, so only true duplicate registrations collapse.
		k := strings.ToLower(e.DisplayName + "|" + e.DisplayVersion + "|" + e.Publisher + "|" + e.Hive + "|" + e.View + "|" +
			strings.TrimRight(strings.TrimSpace(e.InstallLocation), `\/`))
		if seen[k] {
			continue
		}
		seen[k] = true

		p := model.SystemPackage{
			Name:          strings.TrimSpace(e.DisplayName),
			Version:       strings.TrimSpace(e.DisplayVersion),
			Vendor:        strings.TrimSpace(e.Publisher),
			InstallPath:   strings.TrimSpace(e.InstallLocation),
			URL:           strings.TrimSpace(e.URLInfoAbout),
			InstalledSize: int64(e.EstimatedSizeKB) * 1024,
			Source:        "exe",
			Scope:         "machine",
		}
		if e.WindowsInstaller {
			p.Source = "msi"
		}
		if e.Hive == "HKCU" {
			p.Scope = "user"
		} else if e.View == "32" {
			p.Arch = "x86"
		}
		if t, err := time.Parse("20060102", strings.TrimSpace(e.InstallDate)); err == nil {
			p.InstallTimeUnix = t.Unix()
		}
		out = append(out, p)
	}
	return out
}

// nuspec is the subset of a Chocolatey .nuspec we read. Field tags carry no
// namespace so they match regardless of the nuspec schema version.
type nuspec struct {
	Metadata struct {
		ID         string `xml:"id"`
		Version    string `xml:"version"`
		Authors    string `xml:"authors"` // the software's vendor
		Owners     string `xml:"owners"`  // the Chocolatey package maintainers
		ProjectURL string `xml:"projectUrl"`
		License    string `xml:"licenseUrl"`
	} `xml:"metadata"`
}

// chocoPackages reads <root>\lib\<id>\<id>.nuspec, as osquery's
// chocolatey_packages table does.
func (d *WindowsPkgDetector) chocoPackages(root string) []model.SystemPackage {
	lib := filepath.Join(root, "lib")
	ents, err := d.exec.ReadDir(lib)
	if err != nil {
		return nil
	}
	var out []model.SystemPackage
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(lib, e.Name())
		path := filepath.Join(dir, e.Name()+".nuspec")
		data, err := d.exec.ReadFile(path)
		if err != nil {
			continue
		}
		var n nuspec
		if xml.Unmarshal(data, &n) != nil || n.Metadata.ID == "" {
			continue
		}
		p := model.SystemPackage{
			Name:        n.Metadata.ID,
			Version:     n.Metadata.Version,
			Vendor:      n.Metadata.Authors,
			Maintainer:  n.Metadata.Owners,
			URL:         n.Metadata.ProjectURL,
			License:     n.Metadata.License,
			InstallPath: dir,
			Source:      "chocolatey",
			Scope:       "machine",
		}
		// The package dir is created at install; the nuspec keeps the
		// timestamp it had inside the .nupkg.
		if info, err := d.exec.Stat(dir); err == nil && !info.ModTime().IsZero() {
			p.InstallTimeUnix = info.ModTime().Unix()
		}
		out = append(out, p)
	}
	return out
}

type scoopManifest struct {
	Version  string          `json:"version"`
	Homepage string          `json:"homepage"`
	License  json.RawMessage `json:"license"` // string or {"identifier": ...}
}

type scoopInstall struct {
	Bucket       string `json:"bucket"`
	Architecture string `json:"architecture"`
}

// scoopPackages reads <root>\apps\<app>\current\{manifest,install}.json.
// "current" is a junction to the active version directory.
func (d *WindowsPkgDetector) scoopPackages(root, scope string) []model.SystemPackage {
	apps := filepath.Join(root, "apps")
	ents, err := d.exec.ReadDir(apps)
	if err != nil {
		return nil
	}
	var out []model.SystemPackage
	for _, e := range ents {
		current := filepath.Join(apps, e.Name(), "current")
		data, err := readFirst(d.exec, current, "scoop-manifest.json", "manifest.json")
		if err != nil {
			continue
		}
		var m scoopManifest
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		p := model.SystemPackage{
			Name:        e.Name(),
			Version:     m.Version,
			URL:         m.Homepage,
			License:     scoopLicense(m.License),
			InstallPath: current,
			Scope:       scope,
		}
		if real, err := d.exec.EvalSymlinks(current); err == nil {
			p.InstallPath = real
		}
		if data, err := readFirst(d.exec, current, "scoop-install.json", "install.json"); err == nil {
			var inst scoopInstall
			if json.Unmarshal(data, &inst) == nil {
				p.Source = inst.Bucket
				p.Arch = inst.Architecture
			}
		}
		out = append(out, p)
	}
	return out
}

// readFirst reads the first of names present in dir. Scoop 0.6 renamed
// manifest.json / install.json to scoop-manifest.json / scoop-install.json.
func readFirst(exec executor.Executor, dir string, names ...string) ([]byte, error) {
	var err error
	for _, n := range names {
		var data []byte
		if data, err = exec.ReadFile(filepath.Join(dir, n)); err == nil {
			return data, nil
		}
	}
	return nil, err
}

func scoopLicense(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Identifier string `json:"identifier"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Identifier
	}
	return ""
}

// wingetPortablePackages lists winget portable installs: one directory per
// package named <PackageIdentifier>_<SourceIdentifier>. winget registers each
// with an ARP entry under the same key name, which carries the version.
func (d *WindowsPkgDetector) wingetPortablePackages(root, scope string, arpByKey map[string]arpEntry) []model.SystemPackage {
	ents, err := d.exec.ReadDir(root)
	if err != nil {
		return nil
	}
	var out []model.SystemPackage
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		id, source, _ := strings.Cut(e.Name(), "_")
		p := model.SystemPackage{
			Name:        id,
			InstallPath: filepath.Join(root, e.Name()),
			Source:      source,
			Scope:       scope,
		}
		if a, ok := arpByKey[strings.ToLower(e.Name())]; ok {
			p.Version = a.DisplayVersion
			p.Vendor = a.Publisher
		}
		out = append(out, p)
	}
	return out
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func joinIf(base string, rel ...string) string {
	if base == "" {
		return ""
	}
	return filepath.Join(append([]string{base}, rel...)...)
}
