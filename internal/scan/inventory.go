package scan

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"golang.org/x/mod/semver"

	"github.com/step-security/dev-machine-guard/internal/cli"
	"github.com/step-security/dev-machine-guard/internal/detector"
	"github.com/step-security/dev-machine-guard/internal/device"
	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/progress"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// Row flags. The attention rules in attention() read these. Every rule mirrors
// a signal the StepSecurity dashboard shows for the same device, so a developer
// and their admin see the same findings.
const (
	flagRunning      = "running"
	flagRemote       = "remote"
	flagShellAtLoad  = "shell-at-load"
	flagHooks        = "hooks"
	flagDisabled     = "disabled"
	flagDelisted     = "delisted"
	flagStoreFlagged = "store-flagged"
	flagSideloaded   = "sideloaded"
	flagUnpacked     = "unpacked"
	flagPlaintext    = "plaintext"
	flagGitTracked   = "git-tracked"
	flagOthersRead   = "readable-by-others"
	flagDeprecated   = "deprecated"
)

// Developer runs the local collectors for `dmg findings`: no device
// registration, run audit or telemetry.
func Developer(ctx context.Context, exec executor.Executor, cfg *cli.Config, log *progress.Logger) *model.DeveloperReport {
	roots := resolveSearchDirs(exec, cfg.SearchDirs)
	home := executor.ResolveHome(exec)
	skipper := tcc.ForRun(home, cfg.IncludeTCCProtected, cfg.IncludeNetworkVolumes)
	readable := make([]string, 0, len(roots))
	skipped := []string{}
	for _, root := range roots {
		if _, _, err := exec.ReadDirLimit(root, 1); err != nil {
			skipped = append(skipped, root)
			continue
		}
		readable = append(readable, root)
	}
	r, cliTools := collectInventory(ctx, exec, log, cfg, readable, skipper)
	collectSignals(ctx, exec, log, r, cliTools, readable, skipper, device.OSVersion(ctx, exec))

	log.StepStart("Reading MCP server definitions")
	start := time.Now()
	servers := detector.NewMCPDetector(exec).WithSkipper(skipper).DetectEnterprise(ctx, readable)
	log.StepDone(time.Since(start))

	protected := []string{}
	for path := range skipper.Hits() {
		protected = append(protected, path)
	}
	slices.Sort(protected)
	scope := &model.ReportScope{Home: home, SearchDirs: roots, SkippedPaths: skipped, ProtectedPaths: protected}
	return developerView(r, servers, cfg, exec.GOOS(), scope)
}

func developerView(r *model.ScanResult, servers []model.MCPConfigEnterprise, cfg *cli.Config, platform string, scope *model.ReportScope) *model.DeveloperReport {
	rep := &model.DeveloperReport{
		SchemaVersion: model.DeveloperReportSchemaVersion,
		AgentVersion:  r.AgentVersion,
		ScannedAt:     r.ScanTimestampISO,
		Scope:         scope,
		Areas: []model.ReportArea{
			agentsArea(r), mcpArea(r, servers), skillsArea(r), pluginsArea(r),
			extensionsArea(r), browserArea(r), credentialsArea(r),
			projectsArea(r, cfg), packagesArea(r, cfg, platform), runtimesArea(r, cfg),
			{ID: "alerts", Title: "Threat alerts", Status: model.AreaUnavailable, Items: []model.ReportItem{},
				StatusNote: "alerts go to your organization's channels; this device has no local feed yet"},
		},
	}
	for i := range rep.Areas {
		sortItems(rep.Areas[i].Items)
	}
	rep.Attention = attention(rep.Areas)
	return rep
}

func newArea(id, title string) model.ReportArea {
	return model.ReportArea{ID: id, Title: title, Status: model.AreaComplete, Items: []model.ReportItem{}}
}

// Rows that an attention rule matched sort first, so a long table opens on them.
func sortItems(items []model.ReportItem) {
	raised := func(it model.ReportItem) int {
		for _, f := range it.Flags {
			switch f {
			case flagRunning, flagRemote, flagDisabled, flagHooks, flagPlaintext:
			default:
				return 0
			}
		}
		return 1
	}
	slices.SortStableFunc(items, func(a, b model.ReportItem) int {
		return cmp.Or(cmp.Compare(raised(a), raised(b)), strings.Compare(a.Kind, b.Kind),
			strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), strings.Compare(a.Version, b.Version), strings.Compare(a.Location, b.Location))
	})
}

// tally renders "vscode 14, goland 2", largest first.
func tally(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b string) int { return cmp.Or(cmp.Compare(counts[b], counts[a]), strings.Compare(a, b)) })
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, counts[k])
	}
	return strings.Join(parts, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func agentsArea(r *model.ScanResult) model.ReportArea {
	a := newArea("agents", "AI agents and tools")
	names := []string{}
	for _, t := range r.AIAgentsAndTools {
		it := model.ReportItem{Name: t.Name, Version: t.Version, Kind: t.Vendor, Location: cmp.Or(t.BinaryPath, t.InstallPath, t.ConfigDir)}
		if t.IsRunning != nil && *t.IsRunning {
			it.Flags = append(it.Flags, flagRunning)
		}
		a.Items = append(a.Items, it)
		names = append(names, t.Name)
	}
	slices.Sort(names)
	a.Summary = strings.Join(slices.Compact(names), ", ")
	return a
}

func mcpArea(r *model.ScanResult, configs []model.MCPConfigEnterprise) model.ReportArea {
	a := newArea("mcp", "MCP servers")
	withServers, remote := 0, 0
	for _, c := range configs {
		raw, err := base64.StdEncoding.DecodeString(c.ConfigContentBase64)
		if err != nil || len(raw) == 0 {
			continue
		}
		before := len(a.Items)
		for _, s := range mcpServers(raw, strings.HasSuffix(c.ConfigPath, ".toml")) {
			it := model.ReportItem{Name: s.name, Kind: c.ConfigSource, Location: c.ConfigPath}
			switch {
			case s.url != "":
				it.Detail = s.url
				it.Flags = append(it.Flags, flagRemote)
				remote++
			case s.command != "":
				it.Detail = strings.Join(append([]string{s.command}, s.args...), " ")
			}
			if s.project != "" {
				it.Detail = strings.TrimSpace(it.Detail + " · only in " + s.project)
			}
			a.Items = append(a.Items, it)
		}
		if len(a.Items) > before {
			withServers++
		}
	}
	files := max(len(configs), len(r.MCPConfigs))
	if n := len(a.Items); n > 0 {
		a.Summary = fmt.Sprintf("%d local, %d remote · defined in %s", n-remote, remote, plural(withServers, "config file", "config files"))
	} else if files > 0 {
		a.Summary = "no servers defined in " + plural(files, "config file", "config files")
	}
	return a
}

type mcpServer struct {
	name, project, command, url string
	args                        []string
}

// mcpServers reads the detector's filtered config, which keeps only each
// server's command, args and URL, already redacted.
func mcpServers(content []byte, isTOML bool) []mcpServer {
	var doc map[string]any
	if isTOML {
		if toml.Unmarshal(content, &doc) != nil {
			return nil
		}
	} else if json.Unmarshal(content, &doc) != nil {
		return nil
	}
	var out []mcpServer
	add := func(project string, v any) {
		servers, _ := v.(map[string]any)
		for name, raw := range servers {
			fields, _ := raw.(map[string]any)
			s := mcpServer{name: name, project: project}
			s.url, _ = fields["url"].(string)
			if s.url == "" {
				s.url, _ = fields["serverUrl"].(string)
			}
			// OpenCode writes the command and its arguments as one list.
			switch c := fields["command"].(type) {
			case string:
				s.command = c
			case []any:
				s.args = stringList(c)
				if len(s.args) > 0 {
					s.command, s.args = s.args[0], s.args[1:]
				}
			}
			if list, ok := fields["args"].([]any); ok {
				s.args = append(s.args, stringList(list)...)
			}
			out = append(out, s)
		}
	}
	for _, key := range []string{"mcpServers", "mcp_servers", "context_servers", "servers", "mcp"} {
		add("", doc[key])
	}
	projects, _ := doc["projects"].(map[string]any)
	for path, raw := range projects {
		if project, ok := raw.(map[string]any); ok {
			add(path, project["mcpServers"])
		}
	}
	return out
}

func stringList(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// skillsArea lists each skill once. The same definition checked out in several
// worktrees or projects shares a row.
func skillsArea(r *model.ScanResult) model.ReportArea {
	a := newArea("skills", "Agent skills")
	byAgent := map[string]int{}
	index := map[string]int{}
	for _, s := range r.AgentSkills {
		name := cmp.Or(s.SkillName, s.SkillSlug)
		location := cmp.Or(s.SkillDirPath, s.DefinitionPath, s.SkillMDPath)
		hash := cmp.Or(s.SkillMDHash, s.DefinitionHash)
		key := s.Agent + "\x00" + name + "\x00" + hash
		if i, seen := index[key]; seen && hash != "" {
			a.Items[i].Locations = append(a.Items[i].Locations, location)
			continue
		}
		detail := s.Scope
		if s.PluginName != "" {
			detail += " · plugin " + s.PluginName
		}
		it := model.ReportItem{Name: name, Version: s.Version, Kind: s.Agent, Detail: detail, Location: location, Locations: []string{location}}
		if s.HasShellInjection {
			it.Flags = append(it.Flags, flagShellAtLoad)
		}
		if s.HasHooks {
			it.Flags = append(it.Flags, flagHooks)
		}
		index[key] = len(a.Items)
		a.Items = append(a.Items, it)
		byAgent[s.Agent]++
	}
	for i := range a.Items {
		it := &a.Items[i]
		if it.Count = len(it.Locations); it.Count > 1 {
			slices.Sort(it.Locations)
			it.Detail += fmt.Sprintf(" · %d copies", it.Count)
		} else {
			it.Locations, it.Count = nil, 0
		}
	}
	a.Summary = tally(byAgent)
	return a
}

func pluginsArea(r *model.ScanResult) model.ReportArea {
	a := newArea("plugins", "Agent plugins")
	if r.AgentPlugins == nil {
		return a
	}
	byAgent := map[string]int{}
	for _, c := range r.AgentPlugins.Contexts {
		for _, p := range c.Plugins {
			kinds := map[string]int{}
			for _, comp := range p.Components {
				kinds[comp.Kind]++
			}
			detail := []string{p.Scope}
			if len(kinds) > 0 {
				detail = append(detail, tally(kinds))
			}
			it := model.ReportItem{Name: cmp.Or(p.Name, p.ManifestName, p.NativeID), Version: cmp.Or(p.ManifestVersion, p.CacheVersion), Kind: c.Agent,
				Detail: strings.Join(detail, " · "), Location: cmp.Or(p.InstallPath, p.SourcePath)}
			if p.EffectiveEnabled != nil && !*p.EffectiveEnabled {
				it.Flags = append(it.Flags, flagDisabled)
			}
			a.Items = append(a.Items, it)
			byAgent[c.Agent]++
		}
	}
	a.Summary = tally(byAgent)
	return a
}

// unreadReason turns collector reason codes into the cause a developer can act on.
func unreadReason(codes []string, fallback string) string {
	switch {
	case slices.Contains(codes, "refused_tcc"):
		return "macOS privacy protection covers the folder; --include-protected reads it, and macOS may ask you to allow that"
	case slices.Contains(codes, "permission_denied"):
		return "permission denied"
	case slices.Contains(codes, "timed_out"), slices.Contains(codes, "capped"):
		return "the check hit its time or size limit"
	case slices.Contains(codes, "unrecognized_format"):
		return "a file was not in a format the check recognises"
	}
	return fallback
}

func newerVersion(a, b string) bool {
	va, vb := "v"+strings.TrimPrefix(a, "v"), "v"+strings.TrimPrefix(b, "v")
	if semver.IsValid(va) && semver.IsValid(vb) {
		return semver.Compare(va, vb) > 0
	}
	return a > b
}

// extensionsArea keeps the newest copy of each extension. Editors leave older
// versions on disk after an update.
func extensionsArea(r *model.ScanResult) model.ReportArea {
	a := newArea("extensions", "IDE extensions")
	type key struct{ ide, id string }
	index := map[key]int{}
	older := map[key]int{}
	byIDE := map[string]int{}
	for _, x := range r.IDEExtensions {
		k := key{x.IDEType, strings.ToLower(cmp.Or(x.ID, x.Name))}
		it := model.ReportItem{Name: cmp.Or(x.ID, x.Name), Version: x.Version, Kind: x.IDEType, Location: x.InstallPath}
		if i, seen := index[k]; seen {
			older[k]++
			if newerVersion(x.Version, a.Items[i].Version) {
				a.Items[i] = it
			}
			continue
		}
		index[k] = len(a.Items)
		a.Items = append(a.Items, it)
		byIDE[x.IDEType]++
	}
	for k, n := range older {
		a.Items[index[k]].Detail = "+" + plural(n, "older version on disk", "older versions on disk")
	}
	a.Summary = tally(byIDE)
	return a
}

func browserArea(r *model.ScanResult) model.ReportArea {
	a := newArea("browser", "Browser extensions")
	scan := r.BrowserExtensionScan
	if scan == nil {
		a.Status, a.StatusNote = model.AreaUnavailable, "no signed-in user session to inspect"
		return a
	}
	if !scan.ScanComplete {
		codes, browsers := []string{}, []string{}
		for _, b := range scan.Browsers {
			if b.Status == model.BrowserCoverageFailed || b.Status == model.BrowserCoveragePartial {
				codes, browsers = append(codes, b.ReasonCode), append(browsers, b.BrowserID)
			}
		}
		a.Status = model.AreaPartial
		a.StatusNote = strings.TrimSpace(strings.Join(browsers, ", ")+" not read: ") + " " + unreadReason(append(codes, scan.TruncatedReason), "a profile could not be read completely")
	}
	byBrowser := map[string]int{}
	for _, f := range scan.Findings {
		it := model.ReportItem{Name: cmp.Or(f.Name, f.ExtensionID), Version: f.Version, Kind: f.BrowserID, Location: f.InstallPath, Detail: browserAccess(f)}
		enabled := f.EnabledState != model.BrowserExtDisabled
		if !enabled {
			it.Flags = append(it.Flags, flagDisabled)
		}
		// A disabled extension cannot act, so it is listed but never raised.
		if enabled && f.StoreListing == model.BrowserExtStoreListingDelisted {
			it.Flags = append(it.Flags, flagDelisted)
		}
		if enabled && f.StoreViolation == model.BrowserExtStoreViolationFlagged {
			it.Flags = append(it.Flags, flagStoreFlagged)
		}
		if enabled && !f.Preinstalled {
			switch f.InstallSource {
			case model.BrowserExtInstallSideload:
				it.Flags = append(it.Flags, flagSideloaded)
			case model.BrowserExtInstallUnpacked:
				it.Flags = append(it.Flags, flagUnpacked)
			}
		}
		a.Items = append(a.Items, it)
		byBrowser[f.BrowserID]++
	}
	a.Summary = tally(byBrowser)
	return a
}

func browserAccess(f model.BrowserExtensionFinding) string {
	access := plural(len(f.HostPermissions), "site pattern", "site patterns")
	for _, h := range f.HostPermissions {
		if h == "<all_urls>" || strings.HasSuffix(h, "://*/*") {
			access = "all sites"
			break
		}
	}
	if len(f.HostPermissions) == 0 {
		access = "no site access"
	}
	return access + " · " + plural(len(f.Permissions), "permission", "permissions")
}

func credentialsArea(r *model.ScanResult) model.ReportArea {
	a := newArea("credentials", "Credential locations")
	scan := r.CredentialScan
	if scan == nil {
		a.Status, a.StatusNote = model.AreaUnavailable, "the credential-location check did not run"
		return a
	}
	if !scan.ScanComplete {
		codes, sources := []string{}, []string{}
		for _, e := range scan.Errors {
			codes, sources = append(codes, e.ReasonCode), append(sources, e.SourceID)
		}
		a.Status = model.AreaPartial
		a.StatusNote = strings.TrimSpace(listNames(sources)+" not read: ") + " " + unreadReason(codes, "the location could not be read")
	}
	plaintext := 0
	for _, f := range scan.Findings {
		detail := []string{plural(f.Count, "credential", "credentials")}
		if f.Protection != model.CredentialProtectionPlaintext {
			detail = append(detail, f.Protection)
		}
		it := model.ReportItem{Name: f.SourceID, Kind: f.Category, Location: cmp.Or(f.ResolvedLocation, f.Location), Count: f.Count}
		if f.Protection == model.CredentialProtectionPlaintext {
			plaintext++
			it.Flags = append(it.Flags, flagPlaintext)
			if f.GitTracked {
				it.Flags = append(it.Flags, flagGitTracked)
			}
			mode, err := strconv.ParseUint(f.Mode, 8, 32)
			if (err == nil && mode&0o077 != 0) || (f.BroadReadAllowACEPresent != nil && *f.BroadReadAllowACEPresent) {
				it.Flags = append(it.Flags, flagOthersRead)
			}
		}
		if f.Mode != "" {
			detail = append(detail, "mode "+f.Mode)
		}
		it.Detail = strings.Join(detail, " · ")
		a.Items = append(a.Items, it)
	}
	if n := len(a.Items); n > 0 {
		a.Summary = fmt.Sprintf("%d plaintext, %d protected · locations only, never values", plaintext, n-plaintext)
	}
	return a
}

func enabled(v *bool) bool { return v != nil && *v }

// displayVersion drops a manifest "version" that is a Git URL or local path,
// which can carry a private host or token.
func displayVersion(v string) string {
	if strings.ContainsAny(v, ":/@\\") {
		return ""
	}
	return v
}

// projectsArea lists Node.js and Python projects. Projects holding the same
// packages at the same versions, such as git worktrees, share one row.
func projectsArea(r *model.ScanResult, cfg *cli.Config) model.ReportArea {
	a := newArea("projects", "Projects")
	a.Status, a.StatusNote = ecosystemStatus(cfg, false)
	index := map[string]int{}
	total := 0
	add := func(ecosystem string, projects []model.ProjectInfo) {
		for _, p := range projects {
			total++
			kind := cmp.Or(p.PackageManager, ecosystem)
			if len(p.Packages) > 0 {
				lines := make([]string, len(p.Packages))
				for i, pkg := range p.Packages {
					lines[i] = pkg.Name + "\x00" + pkg.Version
				}
				slices.Sort(lines)
				sum := sha256.Sum256([]byte(kind + "\n" + strings.Join(lines, "\n")))
				if i, seen := index[string(sum[:])]; seen {
					a.Items[i].Locations = append(a.Items[i].Locations, p.Path)
					continue
				}
				index[string(sum[:])] = len(a.Items)
			}
			a.Items = append(a.Items, model.ReportItem{Name: p.Path, Kind: kind, Count: len(p.Packages), Locations: []string{p.Path}})
		}
	}
	add("node", r.NodeProjects)
	add("python", r.PythonProjects)
	for i := range a.Items {
		it := &a.Items[i]
		slices.Sort(it.Locations)
		it.Name = slices.MinFunc(it.Locations, func(x, y string) int { return cmp.Or(cmp.Compare(len(x), len(y)), strings.Compare(x, y)) })
		it.Location = it.Name
		it.Detail = plural(it.Count, "package", "packages")
		if n := len(it.Locations) - 1; n > 0 {
			it.Detail += " · +" + plural(n, "identical copy", "identical copies")
		} else {
			it.Locations = nil
		}
	}
	if total > 0 {
		a.Summary = fmt.Sprintf("%d on disk, %d with a distinct package set", total, len(a.Items))
	}
	return a
}

// ecosystemStatus reports which optional package collectors were off.
func ecosystemStatus(cfg *cli.Config, withBrew bool) (status, note string) {
	off := []string{}
	if !enabled(cfg.EnableNPMScan) {
		off = append(off, "Node.js")
	}
	if !enabled(cfg.EnablePythonScan) {
		off = append(off, "Python")
	}
	if withBrew && !enabled(cfg.EnableBrewScan) {
		off = append(off, "Homebrew")
	}
	want := 2
	if withBrew {
		want = 3
	}
	switch len(off) {
	case 0:
		return model.AreaComplete, ""
	case want:
		return model.AreaDisabled, "package scanning is turned off in this device's configuration"
	}
	return model.AreaPartial, strings.Join(off, " and ") + " scanning is turned off in this device's configuration"
}

// packagesArea lists each package once per name and version, with every place
// it is installed.
func packagesArea(r *model.ScanResult, cfg *cli.Config, platform string) model.ReportArea {
	a := newArea("packages", "Packages")
	a.Status, a.StatusNote = ecosystemStatus(cfg, platform == model.PlatformDarwin || platform == model.PlatformLinux)
	type key struct{ kind, name, version string }
	index := map[key]int{}
	byKind := map[string]int{}
	add := func(kind, name, version, location string, flags ...string) {
		k := key{kind, name, version}
		i, seen := index[k]
		if !seen {
			i = len(a.Items)
			index[k] = i
			a.Items = append(a.Items, model.ReportItem{Name: name, Version: version, Kind: kind, Flags: flags})
			byKind[kind]++
		}
		if location != "" {
			a.Items[i].Locations = append(a.Items[i].Locations, location)
		}
	}
	for _, p := range r.NodeProjects {
		for _, pkg := range p.Packages {
			add("npm", pkg.Name, displayVersion(pkg.Version), p.Path)
		}
	}
	for _, p := range r.PythonPackages {
		add("pypi", p.Name, displayVersion(p.Version), "global")
	}
	for _, p := range r.PythonProjects {
		for _, pkg := range p.Packages {
			add("pypi", pkg.Name, displayVersion(pkg.Version), p.Path)
		}
	}
	brew := func(kind string, packages []model.BrewPackage) {
		for _, p := range packages {
			if p.Deprecated {
				add(kind, p.Name, p.Version, p.InstallPath, flagDeprecated)
			} else {
				add(kind, p.Name, p.Version, p.InstallPath)
			}
		}
	}
	brew("brew", r.BrewFormulae)
	brew("cask", r.BrewCasks)
	for _, s := range r.WindowsPackageScans {
		if s.Error != "" {
			a.Status, a.StatusNote = model.AreaPartial, s.ScanType+" packages could not be listed"
		}
		for _, p := range s.Packages {
			add(s.ScanType, p.Name, p.Version, p.InstallPath)
		}
	}
	for _, set := range []struct {
		manager  *model.PkgManager
		packages []model.SystemPackage
	}{{r.SystemPkgManager, r.SystemPackages}, {r.SnapPkgManager, r.SnapPackages}, {r.FlatpakPkgManager, r.FlatpakPackages}} {
		if set.manager != nil {
			for _, p := range set.packages {
				add(set.manager.Name, p.Name, p.Version, p.InstallPath)
			}
		}
	}
	for i := range a.Items {
		it := &a.Items[i]
		slices.Sort(it.Locations)
		it.Locations = slices.Compact(it.Locations)
		it.Count = len(it.Locations)
		if it.Count == 1 {
			it.Location, it.Locations = it.Locations[0], nil
		} else if it.Count > 1 {
			it.Detail = fmt.Sprintf("%d places", it.Count)
		}
	}
	a.Summary = tally(byKind)
	return a
}

func runtimesArea(r *model.ScanResult, cfg *cli.Config) model.ReportArea {
	a := newArea("runtimes", "Runtimes and package managers")
	byRuntime := map[string]int{}
	if cfg.EnableRuntimeScan != nil && !*cfg.EnableRuntimeScan {
		a.Status, a.StatusNote = model.AreaDisabled, "runtime inventory is turned off"
	} else if s := r.RuntimeScan; s != nil {
		for _, p := range s.Runtimes {
			detail := ""
			if p.BundledBy != "" {
				detail = "bundled with " + p.BundledBy
			}
			a.Items = append(a.Items, model.ReportItem{Name: p.Runtime, Version: p.Version, Kind: p.Source, Detail: detail, Location: p.ExecutablePath})
			byRuntime[p.Runtime]++
		}
	}
	managers := slices.Concat(r.NodePkgManagers, r.PythonPkgManagers)
	if r.BrewPkgManager != nil {
		managers = append(managers, *r.BrewPkgManager)
	}
	for _, m := range managers {
		a.Items = append(a.Items, model.ReportItem{Name: m.Name, Version: m.Version, Kind: "package manager", Location: m.Path})
	}
	a.Summary = tally(byRuntime)
	return a
}

// attention turns flagged rows into the short list a developer reads first.
func attention(areas []model.ReportArea) []model.AttentionItem {
	out := []model.AttentionItem{}
	rows := func(area string, match func(model.ReportItem) bool) (names []string) {
		for _, a := range areas {
			if a.ID != area {
				continue
			}
			for _, it := range a.Items {
				if match(it) {
					names = append(names, it.Name)
				}
			}
		}
		return names
	}
	has := func(flags ...string) func(model.ReportItem) bool {
		return func(it model.ReportItem) bool {
			return slices.ContainsFunc(flags, func(f string) bool { return slices.Contains(it.Flags, f) })
		}
	}
	raise := func(severity, area string, names []string, one, many, why string) {
		if len(names) == 0 {
			return
		}
		title := fmt.Sprintf("%d %s", len(names), many)
		if len(names) == 1 {
			title = "1 " + one
		}
		out = append(out, model.AttentionItem{Severity: severity, Area: area, Title: title,
			Detail: listNames(names) + ". " + why, Action: "dmg findings " + area})
	}

	raise(model.AttentionHigh, "credentials", rows("credentials", has(flagGitTracked)),
		"plaintext credential file is tracked in git", "plaintext credential files are tracked in git",
		"A push publishes them. Rotate the credentials and remove the file from history.")
	raise(model.AttentionHigh, "browser", rows("browser", has(flagDelisted, flagStoreFlagged)),
		"enabled browser extension was delisted or flagged by its store", "enabled browser extensions were delisted or flagged by their store",
		"Stores remove extensions for malware and policy violations. Remove it unless you know why it is gone.")
	raise(model.AttentionMedium, "browser", rows("browser", has(flagSideloaded, flagUnpacked)),
		"enabled browser extension was installed outside a store", "enabled browser extensions were installed outside a store",
		"Nothing reviews or updates these. Expected only for extensions you develop.")
	raise(model.AttentionMedium, "skills", rows("skills", has(flagShellAtLoad)),
		"agent skill runs shell commands when it loads", "agent skills run shell commands when they load",
		"The commands run before you see any prompt. Check that you trust their source.")
	plaintext := rows("credentials", func(it model.ReportItem) bool { return has(flagPlaintext)(it) && !has(flagGitTracked)(it) })
	open := len(rows("credentials", func(it model.ReportItem) bool { return has(flagOthersRead)(it) && !has(flagGitTracked)(it) }))
	why := "Any process running as you can read them. Prefer a keychain, a credential helper or short-lived tokens."
	if open > 0 {
		why = fmt.Sprintf("%d can also be read by other accounts on this machine (chmod 600). ", open) + why
	}
	raise(model.AttentionMedium, "credentials", plaintext,
		"location holds credentials in plaintext", "locations hold credentials in plaintext", why)
	raise(model.AttentionInfo, "packages", rows("packages", has(flagDeprecated)),
		"Homebrew package is deprecated upstream", "Homebrew packages are deprecated upstream",
		"They no longer receive fixes.")

	// Only the checks whose coverage the dashboard also reports.
	incomplete := []string{}
	for _, a := range areas {
		if a.Status == model.AreaPartial && (a.ID == "browser" || a.ID == "credentials") {
			incomplete = append(incomplete, strings.ToLower(a.Title))
		}
	}
	if len(incomplete) > 0 {
		title := fmt.Sprintf("%d checks did not finish", len(incomplete))
		if len(incomplete) == 1 {
			title = "1 check did not finish"
		}
		out = append(out, model.AttentionItem{Severity: model.AttentionInfo, Area: "scope", Title: title,
			Detail: listNames(incomplete) + ". Their counts may be low."})
	}
	return out
}

func listNames(names []string) string {
	names = slices.Clone(names)
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) > 4 {
		return strings.Join(names[:3], ", ") + fmt.Sprintf(" and %d more", len(names)-3)
	}
	return strings.Join(names, ", ")
}
