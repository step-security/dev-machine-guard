package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

// Caps and budgets. A hostile skill folder must
// never DoS the run or balloon the payload; every walk and read is bounded.
const (
	maxSkillWalkDepth   = 10      // recursive discovery + intra-skill walk
	maxDirsPerRoot      = 2000    // dirs visited per root before truncating
	maxSkillsPerRoot    = 500     // skill dirs emitted per root before truncating
	maxSkillsTotal      = 2000    // aggregate skill records emitted across all roots (matches backend payload cap)
	maxProjects         = 200     // project roots probed (sorted, deterministic)
	maxSkillMDReadBytes = 1 << 20 // 1 MiB SKILL.md frontmatter read cap
	maxJSONConfigBytes  = 5 << 20 // 5 MiB cap on a parsed JSON config (lock file)
	maxDescriptionRunes = 1024    // standard hard max
	maxNameRunes        = 128     // standard max is 64; we tolerate + record nonconforming
	maxLicenseRunes     = 128
	maxScanErrors       = 50               // bounded error list
	maxScanErrorLen     = 256              // per-error char cap
	skillsPhaseBudget   = 60 * time.Second // overall phase deadline
)

// Home-walk caps. Package-level vars (not const) so the truncation paths can be
// exercised in tests without materializing pathological directory trees; the
// values are the production defaults.
var (
	maxHomeWalkDirs       = 100_000 // ReadDir calls across all search dirs before truncating
	maxHomeWalkDepth      = 12      // recursion depth below each search-dir root
	maxHomeWalkCandidates = 1_000   // project-root candidates emitted before truncating
)

// codeExtensions are files an agent or the OS executes directly — the script
// and interpreter types that make has_code a "this skill could run code"
// signal. Compiled languages (.go/.rs/.c/…) are intentionally excluded: they
// need a build step, so they're a weaker "executes directly" signal and more
// prone to false positives (vendored deps / build artifacts). Keys are
// lowercased, dot-prefixed to match strings.ToLower(filepath.Ext(name)).
var codeExtensions = map[string]bool{
	// Python
	".py": true, ".pyw": true,
	// Node / JS / TS variants
	".js": true, ".ts": true, ".mjs": true, ".cjs": true, ".jsx": true, ".tsx": true,
	// Shell family
	".sh": true, ".bash": true, ".zsh": true, ".fish": true,
	// Windows scripts
	".ps1": true, ".psm1": true, ".bat": true, ".cmd": true,
	// Other interpreters
	".rb": true, ".pl": true, ".php": true, ".lua": true,
}

// hashExcludedNames are files excluded from the census (VCS noise / OS cruft).
// Everything else — including hidden files — is counted, since hidden files can
// hide payloads and are legitimate census members.
var hashExcludedNames = map[string]bool{
	".DS_Store": true,
	"Thumbs.db": true,
}

// SkillsDetector discovers installed AI agent skills across every recognized
// root (global, project, and skills.sh lock-managed). It performs pure
// filesystem reads only — no subprocesses — so it needs no user shell.
type SkillsDetector struct {
	exec          executor.Executor
	skipper       *tcc.Skipper
	now           func() time.Time  // observation time for plugins and skill usage
	agentVersions map[string]string // model.Agent* name → already-collected version
}

// NewSkillsDetector constructs a SkillsDetector.
func NewSkillsDetector(exec executor.Executor) *SkillsDetector {
	return &SkillsDetector{exec: exec, now: time.Now}
}

// WithAgentVersions supplies versions from the AI CLI inventory, keyed by agent name.
func (d *SkillsDetector) WithAgentVersions(v map[string]string) *SkillsDetector {
	d.agentVersions = v
	return d
}

// WithSkipper attaches a TCC skipper so discovery skips macOS-protected
// directories (and projects registered inside them, e.g. under ~/Documents)
// without triggering a permission prompt. A nil skipper is a no-op, matching
// the --include-tcc-protected opt-in. Returns the detector for chaining.
func (d *SkillsDetector) WithSkipper(s *tcc.Skipper) *SkillsDetector {
	d.skipper = s
	return d
}

// CollectProjectRoots flattens the Path of one or more ProjectInfo lists into a
// deduplicated []string, dropping empties. It is the bridge from the node and
// python project scanners to the skills detector's extraProjectRoots argument
// on the community scan path (internal/scan). The enterprise telemetry path has
// its own twin (telemetry.collectProjectRoots) because it carries NodeScanResult
// rather than ProjectInfo. First occurrence wins for ordering — the skills
// detector re-resolves, re-dedupes and sorts internally, so callers need not.
func CollectProjectRoots(lists ...[]model.ProjectInfo) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, p := range list {
			if p.Path == "" || seen[p.Path] {
				continue
			}
			seen[p.Path] = true
			out = append(out, p.Path)
		}
	}
	return out
}

// skillsRoot is one resolved, existing directory to enumerate for skills.
type skillsRoot struct {
	path        string // absolute, existing directory
	source      string // model.AgentSkill.Source value
	agent       string // owning directory convention
	scope       string // "global" | "project" | "system"
	projectPath string // project root for project scope; "" otherwise
	excludeName string // a direct child name to skip (codex .system carve-out)
}

// discoveredSkill is the internal working record for one enumerated skill dir. It
// carries the collapse metadata — whether the root entry was a symlink and the
// symlink-resolved dir that groups shadows of the same physical skill — alongside
// the wire record. collapseSymlinkShadows projects it down to model.AgentSkill.
type discoveredSkill struct {
	rec         model.AgentSkill
	isSymlink   bool   // the entry at its root was a symlink into rec.SkillDirPath
	resolvedDir string // symlink-resolved skill dir — the collapse group key
}

// Detect discovers skills across all roots. extraProjectRoots are additional
// project roots surfaced by the node/python scanners (may be nil); the detector
// also self-discovers projects from ~/.claude.json. It never returns a hard
// error — every failure degrades to an AgentSkillScanInfo.Errors entry and the
// phase keeps going. A non-nil scan info is always returned (the backend "scan
// ran" sentinel), even on partial results. searchDirs (default $HOME) are swept
// for project-convention marker dirs so projects the user never registered in
// ~/.claude.json and that no node/python scanner surfaced are still inventoried;
// passing nil disables the walk (the registry + extra roots still apply).
func (d *SkillsDetector) Detect(ctx context.Context, extraProjectRoots []string, searchDirs []string) ([]model.AgentSkill, *model.AgentSkillScanInfo) {
	r := d.DetectSkills(ctx, extraProjectRoots, searchDirs)
	return r.Skills, r.Info
}

// DetectAll collects both phases for callers that do not track phase progress.
func (d *SkillsDetector) DetectAll(ctx context.Context, extraProjectRoots []string, searchDirs []string) SkillsResult {
	result := d.DetectSkills(ctx, extraProjectRoots, searchDirs)
	if err := d.DetectPlugins(ctx, &result); err != nil {
		d.addError(result.Info, err.Error())
	}
	return result
}

// DetectSkills collects ordinary skills, standalone commands and recorded usage.
// Project discovery and parsed definitions are retained for DetectPlugins.
func (d *SkillsDetector) DetectSkills(ctx context.Context, extraProjectRoots []string, searchDirs []string) (result SkillsResult) {
	start := time.Now()
	info := &model.AgentSkillScanInfo{}
	result.Info = info

	ctx, cancel := context.WithTimeout(ctx, skillsPhaseBudget)
	defer cancel()

	// Preserve partial discoveries and scan status if a read panics.
	var discovered []discoveredSkill
	defer func() {
		if r := recover(); r != nil {
			result.pendingPlugins = nil
			d.addError(info, fmt.Sprintf("panic in skills detect: %v", r))
			// Partial coverage prevents the backend from deleting unseen skills.
			info.Truncated = true
			result.Skills = d.finalizeSkills(discovered, info)
			info.SkillsFound = len(result.Skills)
			info.DurationMs = time.Since(start).Milliseconds()
		}
	}()

	// Per-resolved-path census+hash memo: a skill linked from N roots is hashed
	// exactly once and all N records share the result (symlink dedup).
	memo := map[string]*skillScan{}
	home := getHomeDir(d.exec)
	definitions := 0
	now := time.Now()
	if d.now != nil {
		now = d.now()
	}
	ps := &pluginScan{
		d: d, ctx: ctx, home: home, goos: d.exec.GOOS(), now: now, searchDirs: searchDirs,
		memo: memo, definitions: &definitions, evidence: newPluginEvidence(),
	}
	result.pendingPlugins = ps

	// Global + system roots.
	for _, root := range d.resolveGlobalRoots(info) {
		discovered = append(discovered, d.enumerateRoot(ctx, root, info, memo)...)
	}

	// One state read supplies project roots and usage counters. Project discovery
	// also includes package-scanner roots and bounded filesystem discovery.
	state := readClaudeState(d.exec, d.skipper, home)
	projectInfo := &model.AgentSkillScanInfo{}
	projectCode := state.code
	if projectCode == "" {
		projectCode = state.projectsCode
	}
	if projectCode != "" {
		projectInfo.Truncated = true
		d.addError(projectInfo, fmt.Sprintf("Claude project registry %s: %s", state.path, projectCode))
	}
	walkRoots := d.walkForProjectRoots(ctx, searchDirs, projectInfo)
	projects := d.discoverProjects(state.projects, extraProjectRoots, walkRoots, projectInfo)
	ps.projects = projects
	ps.projectsIncomplete = projectInfo.Truncated || len(projectInfo.Errors) > 0
	info.Truncated = info.Truncated || projectInfo.Truncated
	info.WalkDirsVisited, info.WalkRootsFound = projectInfo.WalkDirsVisited, projectInfo.WalkRootsFound
	for _, err := range projectInfo.Errors {
		d.addError(info, err)
	}
	info.ProjectsScanned = len(projects)
	for _, proj := range projects {
		for _, root := range d.resolveProjectRoots(proj, info) {
			discovered = append(discovered, d.enumerateRoot(ctx, root, info, memo)...)
		}
	}

	// Lock files: parse the global lock + each project lock and join skills.sh
	// provenance onto matching on-disk records. A lock entry with no folder on
	// disk is not an install and is dropped — the inventory is on-disk skills only.
	discovered = d.applyLocks(discovered, projects, info)

	commands := d.enumerateCommands(ctx, home, projects, info, ps)
	if projectInfo.Truncated || len(projectInfo.Errors) > 0 {
		degrade(&info.CommandsStatus, model.AgentScanStatusPartial)
	}
	result.usage = ps.collectClaudeUsage(state)

	// Collapse symlink shadows, sort, and apply the aggregate cap — shared with
	// the panic-recovery path so both return identically bounded, ordered records.
	// Standalone commands are bounded separately and never evict an ordinary skill.
	result.Skills = append(d.finalizeSkills(discovered, info), commands...)
	associateSkillUsage(&result)

	// A deadline or parent cancellation short-circuits the walk, yielding a
	// partial inventory. Mark it truncated so the backend does not treat this scan
	// as authoritative and delete records for skills we simply never reached.
	if ctx.Err() != nil {
		info.Truncated = true
		d.addError(info, fmt.Sprintf("skills phase incomplete: %v", ctx.Err()))
	}

	info.SkillsFound = len(result.Skills)
	info.DurationMs = time.Since(start).Milliseconds()
	return result
}

var strictUintRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type skillUsageObservations struct {
	CollectedAtMs int64
	Sources       []skillUsageSource
}

type skillUsageSource struct {
	SourceID     string
	Agent        string
	SourcePath   string
	Status       string
	AgentVersion string
	Counters     []skillUsageCounter
	Errors       []model.AgentScanError
}

type skillUsageCounter struct {
	RawKey              string
	RecordedUses        int64
	LastRecordedUseAtMs *int64
}

// associateSkillUsage matches native names only when they identify one definition.
// Multiple installation scopes of the same plugin definition share a snapshot.
func associateSkillUsage(result *SkillsResult) {
	if result.usage == nil {
		return
	}
	type candidate struct {
		identity string
		names    []string
		plugin   bool
		usage    **model.SkillUsage
	}
	var candidates []candidate
	for i := range result.Skills {
		s := &result.Skills[i]
		claude := s.Agent == model.AgentClaudeCode || strings.HasPrefix(s.Source, "claude_")
		for _, source := range s.SymlinkSources {
			claude = claude || strings.HasPrefix(source, "claude_")
		}
		if !claude {
			continue
		}
		names := s.CallableNames
		if len(names) == 0 {
			names = []string{s.SkillName}
		}
		definition := s.SkillMDPath
		if s.DefinitionPath != "" {
			definition = s.DefinitionPath
		}
		candidates = append(candidates, candidate{identity: definition, names: names, usage: &s.Usage})
	}
	if result.Plugins != nil {
		for _, context := range result.Plugins.Contexts {
			if context.Agent != model.AgentClaudeCode {
				continue
			}
			for _, plugin := range context.Plugins {
				for _, component := range plugin.Components {
					var usage **model.SkillUsage
					if component.Skill != nil {
						usage = &component.Skill.Usage
					}
					if component.Command != nil {
						usage = &component.Command.Usage
					}
					if usage == nil {
						continue
					}
					origin := plugin.MarketplaceID
					if origin == "" {
						origin = plugin.InstallPath
					}
					identity := inventoryHash(origin, plugin.NativeID, component.Kind, component.RelativePath, component.Name)
					names := component.CallableNames
					if len(names) == 0 {
						names = []string{plugin.Name + ":" + component.Name}
					}
					candidates = append(candidates, candidate{identity: identity, names: names, plugin: true, usage: usage})
				}
			}
		}
	}
	available := map[string]*model.SkillUsage{}
	for _, source := range result.usage.Sources {
		for _, counter := range source.Counters {
			if prev := available[counter.RawKey]; prev != nil && prev.SourceID <= source.SourceID {
				continue
			}
			count := counter.RecordedUses
			available[counter.RawKey] = &model.SkillUsage{Availability: "available", RecordedUses: &count,
				LastRecordedUseAtMs: counter.LastRecordedUseAtMs, RawKey: counter.RawKey, SourceID: source.SourceID, ObservedAtMs: result.usage.CollectedAtMs}
		}
	}
	owners := map[string]map[string]bool{}
	matched := make([][]string, len(candidates))
	for i, candidate := range candidates {
		for _, name := range candidate.names {
			name = strings.TrimPrefix(name, "/")
			if available[name] != nil {
				matched[i] = append(matched[i], name)
			}
		}
		if len(matched[i]) == 0 && candidate.plugin {
			for _, name := range candidate.names {
				name = name[strings.LastIndex(name, ":")+1:]
				if available[name] != nil {
					matched[i] = append(matched[i], name)
				}
			}
		}
		for _, name := range matched[i] {
			if owners[name] == nil {
				owners[name] = map[string]bool{}
			}
			owners[name][candidate.identity] = true
		}
	}
	for i, candidate := range candidates {
		selected := &model.SkillUsage{Availability: "unavailable", ObservedAtMs: result.usage.CollectedAtMs}
		for _, name := range matched[i] {
			if len(owners[name]) != 1 {
				if selected.RecordedUses == nil {
					selected.Availability = "ambiguous"
				}
				continue
			}
			counter := available[name]
			if selected.RecordedUses == nil || *counter.RecordedUses > *selected.RecordedUses ||
				(*counter.RecordedUses == *selected.RecordedUses && counter.RawKey < selected.RawKey) {
				selected = counter
			}
		}
		*candidate.usage = selected
	}
}

// strictUint parses a JSON number that is a plain non-negative integer no
// larger than max. Fractions, exponents, strings and negatives are rejected.
func strictUint(raw json.RawMessage, max int64) (int64, bool) {
	if !strictUintRE.Match(raw) {
		return 0, false
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n > max {
		return 0, false
	}
	return n, true
}

// usageSource projects one state file's skillUsage map into validated observations. Each
// entry is validated on its own; a rejected entry makes the source partial
// without touching the valid keys beside it.
func (s *pluginScan) usageSource(st claudeState, status string) skillUsageSource {
	src := skillUsageSource{
		SourceID: s.usageSourceID(model.AgentClaudeCode, st.path), Agent: model.AgentClaudeCode, SourcePath: st.path,
		Status: status, AgentVersion: s.d.agentVersions[model.AgentClaudeCode],
		Counters: []skillUsageCounter{}, Errors: []model.AgentScanError{},
	}
	code := st.code
	if code == "" {
		code = st.usageCode
	}
	if code != "" {
		src.Status = model.AgentScanStatusError
		scanError(&src.Errors, model.AgentScanError{Code: code, SourcePath: st.path})
		return src
	}
	keys := make([]string, 0, len(st.skillUsage))
	for k := range st.skillUsage {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if len(src.Counters) >= maxUsageCounters {
			degrade(&src.Status, model.AgentScanStatusPartial)
			scanError(&src.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: st.path})
			break
		}
		var entry struct {
			UsageCount json.RawMessage `json:"usageCount"`
			LastUsedAt json.RawMessage `json:"lastUsedAt"`
		}
		count, ok := int64(0), key != "" && len(key) <= maxNameBytes && json.Unmarshal(st.skillUsage[key], &entry) == nil
		if ok {
			count, ok = strictUint(entry.UsageCount, maxRecordedUses)
		}
		var last *int64
		if ok && len(entry.LastUsedAt) > 0 && string(entry.LastUsedAt) != "null" {
			var ms int64
			if ms, ok = strictUint(entry.LastUsedAt, maxRecordedUses); ok {
				last = &ms
			}
		}
		if !ok {
			degrade(&src.Status, model.AgentScanStatusPartial)
			scanError(&src.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: st.path})
			continue
		}
		src.Counters = append(src.Counters, skillUsageCounter{RawKey: key, RecordedUses: count, LastRecordedUseAtMs: last})
	}
	return src
}

// collectClaudeUsage collects usage observations from the home state file and,
// when a custom configuration root is visible, that root's state file. The
// custom layout is not a verified client fixture, so its coverage stays partial.
func (s *pluginScan) collectClaudeUsage(homeState claudeState) *skillUsageObservations {
	var sources []skillUsageSource
	if !homeState.absent {
		sources = append(sources, s.usageSource(homeState, model.AgentScanStatusComplete))
	}
	if cfg := s.d.exec.Getenv("CLAUDE_CONFIG_DIR"); cfg != "" {
		if st := readClaudeState(s.d.exec, s.d.skipper, filepath.Clean(cfg)); !st.absent && st.path != homeState.path {
			sources = append(sources, s.usageSource(st, model.AgentScanStatusPartial))
		}
	}
	if len(sources) == 0 {
		return nil
	}
	sort.SliceStable(sources, func(i, j int) bool { return sources[i].SourcePath < sources[j].SourcePath })
	if len(sources) > maxUsageSources {
		sources = sources[:maxUsageSources]
	}
	remaining, errors := maxUsageCounters, 0
	for i := range sources {
		source := &sources[i]
		if len(source.Counters) > remaining {
			source.Counters = source.Counters[:remaining]
			degrade(&source.Status, model.AgentScanStatusPartial)
			scanError(&source.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: source.SourcePath})
		}
		remaining -= len(source.Counters)
		errors = capErrors(&source.Errors, errors)
	}
	scan := &skillUsageObservations{CollectedAtMs: s.now.UnixMilli(), Sources: sources}
	if encodedSize(scan) > maxEnvelopeBytes {
		for i := len(scan.Sources) - 1; i >= 0 && encodedSize(scan) > maxEnvelopeBytes; i-- {
			source := &scan.Sources[i]
			degrade(&source.Status, model.AgentScanStatusPartial)
			scanError(&source.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: source.SourcePath})
			for len(source.Counters) > 0 && encodedSize(scan) > maxEnvelopeBytes {
				source.Counters = source.Counters[:len(source.Counters)/2]
			}
		}
	}
	errors = 0
	for i := range scan.Sources {
		errors = capErrors(&scan.Sources[i].Errors, errors)
	}
	return scan
}

// claudeConfigRoot is ~/.claude, or CLAUDE_CONFIG_DIR when visible to this process.
func (d *SkillsDetector) claudeConfigRoot(home string) string {
	if cfg := d.exec.Getenv("CLAUDE_CONFIG_DIR"); cfg != "" {
		return cfg
	}
	return filepath.Join(home, ".claude")
}

// enumerateCommands inventories standalone Claude command Markdown files under
// the user commands root and each discovered project's .claude/commands. Each
// file is one AgentSkill row of definition kind "command"; the callable name
// comes from the path, and no skill-directory fields are invented. Coverage is
// reported through info.CommandsStatus.
func (d *SkillsDetector) enumerateCommands(ctx context.Context, home string, projects []string, info *model.AgentSkillScanInfo, ps *pluginScan) []model.AgentSkill {
	type cmdRoot struct{ dir, source, scope, project string }
	roots := []cmdRoot{{filepath.Join(d.claudeConfigRoot(home), "commands"), "claude_user", "global", ""}}
	for _, proj := range projects {
		roots = append(roots, cmdRoot{filepath.Join(proj, ".claude", "commands"), "claude_project", "project", proj})
	}
	status := model.AgentScanStatusComplete
	var out []model.AgentSkill
	for _, root := range roots {
		budget := min(maxNewDefinitions-*ps.definitions, maxNewDefinitions-len(out))
		if budget <= 0 {
			status = model.AgentScanStatusPartial
			break
		}
		if d.skipper.WithinProtected(root.dir) {
			status = model.AgentScanStatusPartial
			continue
		}
		guarded := *d
		guarded.exec = d.exec.GuardedFiles([]string{home, root.dir, root.project}, func(p string) string {
			if d.skipper.WithinProtected(p) {
				return "tcc_protected"
			}
			return ""
		}, maxSkillMDReadBytes)
		if state, _, _ := ps.stat(&guarded, root.dir); state != fileDir {
			if state != fileAbsent {
				status = model.AgentScanStatusPartial
			}
			continue
		}

		var files []string
		dirs := 0
		stopped := false
		var walk func(dir string, depth int)
		walk = func(dir string, depth int) {
			if stopped {
				return
			}
			if ctx.Err() != nil || depth > maxSkillWalkDepth {
				status = model.AgentScanStatusPartial
				return
			}
			if dirs++; dirs > maxDirsPerRoot {
				status = model.AgentScanStatusPartial
				return
			}
			entries, err := guarded.exec.ReadDir(dir)
			if err != nil {
				status = model.AgentScanStatusPartial
				d.addError(info, fmt.Sprintf("read commands dir %s: %v", dir, err))
				return
			}
			for _, name := range sortedEntryNames(entries) {
				if stopped {
					return
				}
				ent := dirEntryByName(entries, name)
				switch {
				case ent.Type()&os.ModeSymlink != 0:
				case ent.IsDir():
					walk(filepath.Join(dir, name), depth+1)
				case ent.Type().IsRegular() && strings.HasSuffix(name, ".md"):
					if len(files) >= budget {
						status = model.AgentScanStatusPartial
						stopped = true
						return
					}
					files = append(files, filepath.Join(dir, name))
				}
			}
		}
		walk(root.dir, 0)

		for _, file := range files {

			rel, _ := relSlash(root.dir, file)
			stem := strings.TrimSuffix(path.Base(rel), ".md")
			rec := model.AgentSkill{
				SkillSlug: stem, SkillName: stem, Agent: model.AgentClaudeCode, Source: root.source, Scope: root.scope, ProjectPath: root.project,
				DefinitionKind: model.AgentDefinitionCommand, DefinitionPath: file, CallableNames: []string{"/" + commandCallable(rel)},
			}
			meta := ps.commandMetadata(&guarded, file)
			if meta.frontmatterError == "invalid_yaml" {
				status = model.AgentScanStatusPartial
			}
			switch meta.readError {
			case "":
				rec.DefinitionHash = meta.hash
				rec.HasFrontmatter, rec.FrontmatterError = meta.hasFrontmatter, meta.frontmatterError
				rec.Description, rec.Version, rec.License, rec.AllowedTools = meta.description, meta.version, meta.license, meta.allowedTools
				rec.DisableModelInvocation, rec.UserInvocableDisabled = meta.disableModelInvoc, meta.userInvocDisabled
				rec.HasHooks, rec.HasShellInjection = meta.hasHooks, meta.hasShellInjection
			case model.AgentScanErrLimitExceeded:
				rec.FrontmatterError = "file_too_large"
				status = model.AgentScanStatusPartial
			default:
				rec.FrontmatterError = "unreadable"
				status = model.AgentScanStatusPartial
			}
			out = append(out, rec)
		}
	}
	if ctx.Err() != nil {
		status = model.AgentScanStatusPartial
	}
	info.CommandsStatus = status
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.ProjectPath != b.ProjectPath {
			return a.ProjectPath < b.ProjectPath
		}
		return a.DefinitionPath < b.DefinitionPath
	})
	return out
}

// finalizeSkills projects the accumulated discoveries into the final record
// list: collapse symlink shadows (one record per physical skill dir, the linked
// roots recorded in symlink_sources), sort deterministically by (source,
// project_path, skill_slug), and enforce the aggregate cap. The per-root caps
// reset per root, so the total can exceed the backend's payload limit; capping
// the sorted list keeps the retained prefix deterministic and matched to the
// backend's own truncation, and Truncated tells the backend the scan is
// non-authoritative so it suppresses deletions. Detect's normal return and its
// panic-recovery path both funnel through here so a late panic cannot bypass
// the cap.
func (d *SkillsDetector) finalizeSkills(discovered []discoveredSkill, info *model.AgentSkillScanInfo) []model.AgentSkill {
	skills := collapseSymlinkShadows(discovered)
	sortSkills(skills)
	if len(skills) > maxSkillsTotal {
		info.Truncated = true
		d.addError(info, fmt.Sprintf("skills truncated: %d found, capped at %d", len(skills), maxSkillsTotal))
		skills = skills[:maxSkillsTotal]
	}
	return skills
}

// resolveGlobalRoots expands the global/system source table for the
// scanning user's home, per-OS, filtering to directories that exist. Existing
// roots are appended to info.RootsScanned.
func (d *SkillsDetector) resolveGlobalRoots(info *model.AgentSkillScanInfo) []skillsRoot {
	home := getHomeDir(d.exec)
	win := d.exec.GOOS() == model.PlatformWindows
	var roots []skillsRoot

	addRoot := func(root skillsRoot) {
		// WithinProtected before DirExists: DirExists stats, and a stat inside a
		// protected tree fires the prompt. Defense-in-depth — today's global roots
		// (~/.claude, /etc/codex, …) never live under a protected dir, but a future
		// one might.
		if root.path == "" || d.skipper.WithinProtected(root.path) || !d.exec.DirExists(root.path) {
			return
		}
		roots = append(roots, root)
		info.RootsScanned = append(info.RootsScanned, root.path)
	}
	add := func(pathStr, source, agent, scope, excludeName string) {
		addRoot(skillsRoot{path: pathStr, source: source, agent: agent, scope: scope, excludeName: excludeName})
	}

	// claude_user: ~/.claude/skills, honoring CLAUDE_CONFIG_DIR when the env
	// var is visible to this process (not under a daemon that can't see it).
	add(filepath.Join(d.claudeConfigRoot(home), "skills"), "claude_user", "claude-code", "global", "")

	// agents_user: ~/.agents/skills — the shared cross-client convention read by
	// skills.sh, Zed, and the Gemini CLI (~/.agents is Gemini's alias for its own
	// ~/.gemini root), hence the "shared" agent label.
	add(filepath.Join(home, ".agents", "skills"), "agents_user", "shared", "global", "")

	// codex_user: ~/.codex/skills, excluding the vendor .system subdir from
	// the normal walk; .system is emitted separately as codex_system.
	codexSkills := filepath.Join(home, ".codex", "skills")
	add(codexSkills, "codex_user", "codex", "global", ".system")
	add(filepath.Join(codexSkills, ".system"), "codex_system", "codex", "global", "")

	// opencode_user: ~/.config/opencode/{skills,skill} (both honored).
	add(filepath.Join(home, ".config", "opencode", "skills"), "opencode_user", "opencode", "global", "")
	add(filepath.Join(home, ".config", "opencode", "skill"), "opencode_user", "opencode", "global", "")

	// codex_admin: machine-global admin scope.
	if win {
		add(resolveEnvPath(d.exec, `%ProgramData%\OpenAI\Codex`), "codex_admin", "codex", "system", "")
	} else {
		add("/etc/codex/skills", "codex_admin", "codex", "system", "")
	}

	// cursor_user: ~/.cursor/skills.
	add(filepath.Join(home, ".cursor", "skills"), "cursor_user", "cursor", "global", "")

	// gemini_user: ~/.gemini/skills (Gemini CLI workspace skills; the ~/.agents
	// alias tier is already covered by agents_user above).
	add(filepath.Join(home, ".gemini", "skills"), "gemini_user", "gemini-cli", "global", "")

	// pi_user: ~/.pi/agent/skills (note the "agent" path segment).
	add(filepath.Join(home, ".pi", "agent", "skills"), "pi_user", "pi", "global", "")

	// factory_user: ~/.factory/skills.
	add(filepath.Join(home, ".factory", "skills"), "factory_user", "factory", "global", "")

	// amp_user: ~/.config/agents/skills (XDG global; a distinct path from
	// agents_user's ~/.agents/skills).
	add(filepath.Join(home, ".config", "agents", "skills"), "amp_user", "amp", "global", "")

	// copilot_user: ~/.copilot/skills.
	add(filepath.Join(home, ".copilot", "skills"), "copilot_user", "copilot", "global", "")

	// amp_user also covers ~/.config/amp/skills — Amp's own root, third in its
	// precedence list — under the same source label, two roots, as with
	// opencode_user above.
	add(filepath.Join(home, ".config", "amp", "skills"), "amp_user", "amp", "global", "")

	// factory_agent_user: ~/.agent/skills — the singular-.agent compat root
	// that Factory AND Antigravity both read, so the agent is "shared" (as
	// for ~/.agents); the source label is kept for compatibility. The plural
	// ~/.agents/skills above is the shared convention, and the project-level
	// .agent/skills is factory_agent_project.
	add(filepath.Join(home, ".agent", "skills"), "factory_agent_user", "shared", "global", "")

	// kiro_user: ~/.kiro/skills — one root shared by the Kiro IDE and CLI.
	add(filepath.Join(home, ".kiro", "skills"), "kiro_user", "kiro", "global", "")

	// windsurf_user, and windsurf_system: the admin-managed root, per OS.
	add(filepath.Join(home, ".codeium", "windsurf", "skills"), "windsurf_user", "windsurf", "global", "")
	switch d.exec.GOOS() {
	case model.PlatformDarwin:
		add("/Library/Application Support/Windsurf/skills", "windsurf_system", "windsurf", "system", "")
	case model.PlatformWindows:
		add(resolveEnvPath(d.exec, `%ProgramData%\Windsurf\skills`), "windsurf_system", "windsurf", "system", "")
	default:
		add("/etc/windsurf/skills", "windsurf_system", "windsurf", "system", "")
	}

	// antigravity_user: Antigravity's own root plus the skills.sh destination,
	// both under ~/.gemini and neither read by the Gemini CLI (gemini_user).
	add(filepath.Join(home, ".gemini", "config", "skills"), "antigravity_user", "antigravity", "global", "")
	add(filepath.Join(home, ".gemini", "antigravity", "skills"), "antigravity_user", "antigravity", "global", "")

	// openclaw_user: the managed root; openclaw_project: the default agent
	// workspace, with the workspace as the project path. Named
	// (workspace-<id>) and relocated workspaces are not discovered.
	openclaw := filepath.Join(home, ".openclaw")
	add(filepath.Join(openclaw, "skills"), "openclaw_user", "openclaw", "global", "")
	workspace := filepath.Join(openclaw, "workspace")
	addRoot(skillsRoot{
		path: filepath.Join(workspace, "skills"), source: "openclaw_project", agent: "openclaw",
		scope: "project", projectPath: workspace,
	})

	// grok_user / kimi_user / muse_user: each agent's own global root. All
	// three also read ~/.agents/skills, which stays attributed to agents_user.
	add(filepath.Join(home, ".grok", "skills"), "grok_user", "grok-build", "global", "")
	add(filepath.Join(home, ".kimi-code", "skills"), "kimi_user", "kimi-code", "global", "")
	add(filepath.Join(home, ".config", "muse", "skills"), "muse_user", "muse-code", "global", "")

	// hermes_user: ~/.hermes/skills holds the bundled skills the installer
	// copies, nested one category deep (<category>/<skill>/SKILL.md), plus
	// .bundled_manifest and .hub/ metadata that enumerateRoot ignores. Windows
	// keeps HERMES_HOME under %LOCALAPPDATA%.
	if win {
		add(resolveEnvPath(d.exec, `%LOCALAPPDATA%\hermes\skills`), "hermes_user", "hermes-agent", "global", "")
	} else {
		add(filepath.Join(home, ".hermes", "skills"), "hermes_user", "hermes-agent", "global", "")
	}

	// omp_user / omp_managed_user: Oh My Pi's user skills and the managed
	// skills it syncs, both under its ~/.omp/agent root.
	add(filepath.Join(home, ".omp", "agent", "skills"), "omp_user", "oh-my-pi", "global", "")
	add(filepath.Join(home, ".omp", "agent", "managed-skills"), "omp_managed_user", "oh-my-pi", "global", "")

	return roots
}

// resolveProjectRoots expands the project-relative skill dirs for one project
// root, filtering to existing dirs and appending them to info.RootsScanned. It
// is the authority on which per-project skill dirs exist; projectMarkerDirs
// mirrors this list for the home walk and MUST be kept in lockstep with it.
func (d *SkillsDetector) resolveProjectRoots(project string, info *model.AgentSkillScanInfo) []skillsRoot {
	var roots []skillsRoot
	add := func(rel []string, source, agent string) {
		p := filepath.Join(append([]string{project}, rel...)...)
		// WithinProtected before DirExists (which stats): second layer behind the
		// discoverProjects guard, so a protected project root that ever reached
		// here still cannot pop a prompt via a per-project skill dir probe.
		if d.skipper.WithinProtected(p) || !d.exec.DirExists(p) {
			return
		}
		roots = append(roots, skillsRoot{
			path: p, source: source, agent: agent, scope: "project", projectPath: project,
		})
		info.RootsScanned = append(info.RootsScanned, p)
	}
	add([]string{".claude", "skills"}, "claude_project", "claude-code")
	add([]string{".agents", "skills"}, "agents_project", "shared") // shared convention: skills.sh, Zed, Gemini alias
	add([]string{".opencode", "skills"}, "opencode_project", "opencode")
	add([]string{".opencode", "skill"}, "opencode_project", "opencode")
	add([]string{".cursor", "skills"}, "cursor_project", "cursor")
	add([]string{".pi", "skills"}, "pi_project", "pi")
	add([]string{".factory", "skills"}, "factory_project", "factory")
	add([]string{".agent", "skills"}, "factory_agent_project", "shared") // singular .agent — read by Factory and Antigravity, so shared; label kept for compatibility
	add([]string{".github", "skills"}, "github_project", "copilot")      // only .github/skills, never the rest of .github
	add([]string{".gemini", "skills"}, "gemini_project", "gemini-cli")
	add([]string{".aider", "skills"}, "aider_project", "aider") // community convention: loaded manually, but on-disk state is inventoried
	add([]string{".kiro", "skills"}, "kiro_project", "kiro")    // shared by Kiro IDE and CLI
	add([]string{".windsurf", "skills"}, "windsurf_project", "windsurf")
	add([]string{".codex", "skills"}, "codex_project", "codex") // Codex project skills (also the JetBrains Codex install target)
	add([]string{".grok", "skills"}, "grok_project", "grok-build")
	add([]string{".kimi-code", "skills"}, "kimi_project", "kimi-code")
	add([]string{".hermes", "skills"}, "hermes_project", "hermes-agent")
	add([]string{".omp", "skills"}, "omp_project", "oh-my-pi") // Muse has no agent-specific project root; it reads .agents/.codex/.claude
	return roots
}

// projectMarkerDirs maps each project-convention dot-directory name to the child
// directory name(s) whose presence marks the dot-dir's parent as a project root.
// Keep in lockstep with resolveProjectRoots: that function is the authority on
// which per-project skill dirs are probed once a project is known, and this
// table is how walkForProjectRoots recognizes a project it was never told about.
// A change to one MUST change the other.
var projectMarkerDirs = map[string][]string{
	".claude":    {"skills"},
	".agents":    {"skills"},
	".opencode":  {"skills", "skill"}, // both spellings, same as resolveProjectRoots
	".cursor":    {"skills"},
	".pi":        {"skills"},
	".factory":   {"skills"},
	".agent":     {"skills"}, // singular — Factory legacy, distinct from .agents
	".github":    {"skills"}, // only .github/skills, never the rest of .github
	".gemini":    {"skills"}, // Gemini CLI workspace skills
	".aider":     {"skills"}, // Aider community convention (skills loaded manually)
	".grok":      {"skills"},
	".kimi-code": {"skills"},
	".hermes":    {"skills"},
	".omp":       {"skills"},
	".kiro":      {"skills"},
	".windsurf":  {"skills"},
	".codex":     {"skills"},
}

// walkForProjectRoots sweeps each search dir for projectMarkerDirs and returns
// the marker dirs' parent directories as project-root candidates for
// discoverProjects to union in. It exists because there is no "where does code
// live" convention to exploit, so the only way to inventory a project the user
// never registered in ~/.claude.json and that no node/python scanner surfaced is
// to look for the marker conventions directly.
//
// The walk's only filesystem primitive is executor.ReadDir, invoked only on
// directories proven to lie outside every TCC-protected tree. Each search root is
// first normalized to an absolute path, rejected if it lies at or under a
// protected tree (before any ReadDir — under the default skipper-on posture the
// walk never enters one; --include-tcc-protected is the opt-in), deduped (a root
// nested under an accepted one is skipped), and skipped if any component of its
// path is a symlink or non-directory (classified by listing each ancestor
// top-down, never following a link). While descending, a protected subtree is pruned by
// ShouldSkip BEFORE its ReadDir, directory symlinks are recognized from the
// parent listing and never followed, and every non-marker dot-dir plus
// node_modules (and, on Windows, the big system trees) is pruned. No Stat /
// DirExists / EvalSymlinks / ReadFile ever runs, so macOS serves the walk without
// touching entries and no permission prompt can fire. Candidates are deduped on
// the absolute path here; discoverProjects re-resolves, re-guards
// (WithinProtected), home-excludes, dedupes, and caps them. Every cap trip flags
// info.Truncated with a bounded error, matching the existing walks.
func (d *SkillsDetector) walkForProjectRoots(ctx context.Context, searchDirs []string, info *model.AgentSkillScanInfo) []string {
	var candidates []string
	seen := map[string]bool{}
	dirsVisited := 0
	stopped := false
	win := d.exec.GOOS() == model.PlatformWindows

	// charge accounts for one ReadDir against the dir budget and trips truncation
	// (once) when it is exhausted. Both the walk's own ReadDir and every marker
	// probe charge, so a wide fan-out of marker dirs cannot evade the cap.
	charge := func() bool {
		// Check before incrementing so WalkDirsVisited counts ReadDir calls
		// actually made and never overshoots the cap by one.
		if dirsVisited >= maxHomeWalkDirs {
			if !stopped {
				stopped = true
				info.Truncated = true
				d.addError(info, fmt.Sprintf("home walk truncated at %d dirs", maxHomeWalkDirs))
			}
			return false
		}
		dirsVisited++
		return true
	}

	// emit records one project-root candidate, deduping on the raw path and
	// tripping truncation (once) at the candidate cap.
	emit := func(dir string) {
		if seen[dir] {
			return
		}
		if len(candidates) >= maxHomeWalkCandidates {
			if !stopped {
				stopped = true
				info.Truncated = true
				d.addError(info, fmt.Sprintf("home walk candidates truncated at %d", maxHomeWalkCandidates))
			}
			return
		}
		seen[dir] = true
		candidates = append(candidates, dir)
	}

	var walk func(dir, root string, depth int)
	walk = func(dir, root string, depth int) {
		if stopped || ctx.Err() != nil {
			return
		}
		// TCC choke: the first filesystem op inside a protected tree is what fires
		// the prompt, so ShouldSkip runs before the ReadDir. Nil-safe (opt-in mode).
		if d.skipper.ShouldSkip(dir, root) {
			return
		}
		if !charge() {
			return
		}
		entries, err := d.exec.ReadDir(dir)
		if err != nil {
			// A search root that cannot be listed means an entire discovery source
			// may be missing — mark the scan partial so the backend keeps it
			// non-authoritative and suppresses deletions. Deeper per-dir failures
			// are localized and deterministic, so they do NOT flip authority (doing
			// so would strand deletion suppression on every scan of such a machine).
			if depth == 0 {
				info.Truncated = true
			}
			d.addError(info, fmt.Sprintf("home walk read dir %s: %v", dir, err))
			return
		}

		entMap := make(map[string]os.DirEntry, len(entries))
		for _, e := range entries {
			entMap[e.Name()] = e
		}
		for _, name := range sortedEntryNames(entries) {
			if stopped || ctx.Err() != nil {
				return
			}
			ent := entMap[name]
			// Directory symlinks are inert: recognized from the parent listing (no
			// stat) and never followed, so the walk cannot be steered into a
			// protected tree, another user's home, a network mount, or a cycle.
			if ent.Type()&os.ModeSymlink != 0 {
				continue
			}
			if !ent.IsDir() {
				continue // a plain file never classifies a project
			}
			childDir := filepath.Join(dir, name)

			if markerChildren, ok := projectMarkerDirs[name]; ok {
				// A marker dot-dir (e.g. .claude): its parent `dir` is a project root
				// iff the marker dir itself holds the expected skills child. Probe by
				// listing the marker dir (charged to the budget); never descend past
				// it — enumerating the skills inside is enumerateRoot's job, reached
				// via the normal project pipeline once discoverProjects admits `dir`.
				if !charge() {
					return
				}
				mEntries, err := d.exec.ReadDir(childDir)
				if err != nil {
					d.addError(info, fmt.Sprintf("home walk read marker %s: %v", childDir, err))
					continue
				}
				if hasMarkerChild(mEntries, markerChildren) {
					emit(dir)
				}
				continue
			}
			if strings.HasPrefix(name, ".") {
				continue // every other hidden tree (.git, .cache, .venv, …)
			}
			if name == "node_modules" || (win && isWindowsNoiseDir(name)) {
				continue
			}
			if depth+1 <= maxHomeWalkDepth {
				walk(childDir, root, depth+1)
			}
		}
	}

	// rootIsRealDir reports whether root is a real directory reachable WITHOUT
	// following any symlink, verified by listing each ANCESTOR top-down (never the
	// root itself — the walk does that). Resolving the path directly
	// (EvalSymlinks/Stat) would dereference a symlinked component into its target;
	// for ~/link/sub with link -> ~/Documents that means statting inside a
	// protected tree — the very TCC prompt the walk exists to avoid. Each ancestor
	// is confirmed unprotected BEFORE it is listed, and a symlink or non-directory
	// anywhere on the path is rejected without being followed, so a symlinked
	// COMPONENT (not just the final one) cannot steer a ReadDir into a protected
	// tree. Every ancestor ReadDir is charged, so root validation counts against
	// the dir budget and WalkDirsVisited. ReadDir stays the only filesystem
	// primitive; this matches filepath.WalkDir, which never descends a root it
	// cannot Lstat as a directory.
	rootIsRealDir := func(root string) bool {
		var chain []string // [root, parent, …, anchor]
		for p := root; ; {
			chain = append(chain, p)
			parent := filepath.Dir(p)
			if parent == p {
				break // filesystem anchor ("/" or a volume root)
			}
			p = parent
		}
		// Descend anchor -> root, classifying each child from its parent's listing.
		for i := len(chain) - 1; i > 0; i-- {
			parent, child := chain[i], chain[i-1]
			if d.skipper.WithinProtected(parent) {
				return false // listing a protected ancestor would prompt; --include-tcc-protected opts in
			}
			if !charge() {
				return false
			}
			entries, err := d.exec.ReadDir(parent)
			if err != nil {
				return false
			}
			base := filepath.Base(child)
			var found os.DirEntry
			for _, e := range entries {
				if e.Name() == base {
					found = e
					break
				}
			}
			if found == nil || !found.IsDir() || found.Type()&os.ModeSymlink != 0 {
				return false
			}
		}
		return true
	}

	// isUnder reports whether p is at or below any of roots (path-boundary match).
	isUnder := func(p string, roots []string) bool {
		for _, r := range roots {
			if p == r || strings.HasPrefix(p, r+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}

	// Normalize each search root to an absolute, lexically-clean path (filepath.Abs
	// consults only os.Getwd — no stat), drop any at or under a protected tree
	// before any filesystem op (the default skipper-on posture never enters one;
	// --include-tcc-protected is the opt-in), and dedupe. A relative root could
	// never match an absolute TCC tree, and a bare "." would ReadDir the process
	// CWD and later be admitted as the project ".", duplicating every global skill.
	home := getHomeDir(d.exec)
	seenRoots := map[string]bool{}
	var roots []string
	for _, sd := range searchDirs {
		if sd == "" {
			continue
		}
		root := canonicalNoStat(sd, home)
		if d.skipper.WithinProtected(root) || seenRoots[root] {
			continue
		}
		seenRoots[root] = true
		roots = append(roots, root)
	}
	// Sort so a nested root is processed after the ancestor that already covers it,
	// letting isUnder skip the overlap (e.g. $HOME then $HOME/work) instead of
	// re-walking the same tree and double-charging the budget.
	sort.Strings(roots)
	var accepted []string
	for _, root := range roots {
		if stopped {
			break
		}
		if isUnder(root, accepted) {
			continue // an already-accepted ancestor root walks this subtree
		}
		if !rootIsRealDir(root) {
			d.addError(info, fmt.Sprintf("home walk skipped non-directory or symlinked search root %s", root))
			continue
		}
		accepted = append(accepted, root)
		walk(root, root, 0)
	}

	info.WalkDirsVisited = dirsVisited
	info.WalkRootsFound = len(candidates)
	return candidates
}

// hasMarkerChild reports whether entries contains a real (non-symlink) directory
// named one of want. A symlink-typed child is deliberately not a match: honoring
// it would require resolving the link (a stat), reintroducing a TCC residual on a
// new path. skills.sh farms symlinks at the skill level, not the container level,
// and a registered project with a symlinked container still resolves via
// resolveProjectRoots — pre-existing behavior, not widened here.
func hasMarkerChild(entries []os.DirEntry, want []string) bool {
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() {
			continue
		}
		if slices.Contains(want, e.Name()) {
			return true
		}
	}
	return false
}

// isWindowsNoiseDir reports whether name is a Windows system directory that holds
// no project roots but enormous, junction-heavy trees — pruned by name for cost.
// (The junctions inside surface as symlink-typed entries and are skipped anyway.)
func isWindowsNoiseDir(name string) bool {
	switch name {
	case "AppData", "Application Data", "$RECYCLE.BIN", "System Volume Information":
		return true
	}
	return false
}

// discoverProjects unions Claude Code's project registry with node/python roots
// (extra) and home-walk discoveries (walkRoots), dedupes on absolute
// symlink-resolved path, drops stale (missing) dirs and the home directory
// itself, and caps at maxProjects (deterministic). Home is excluded because its
// dotfile skill dirs (~/.claude/skills, ~/.agents/skills, …) are already the
// global roots; treating home as a project would re-scan those same dirs and
// re-emit every global skill as a project-scoped duplicate.
//
// The registry and extra roots are an authoritative tier: a registered or
// scanner-surfaced project must never be evicted from the cap by a walk
// discovery, so they are admitted first (sorted) and the walk fills only the
// capacity they leave (also sorted). With no walkRoots the result is identical
// to registry∪extra alone — the walk can add projects but never displace one.
func (d *SkillsDetector) discoverProjects(registry, extra, walkRoots []string, info *model.AgentSkillScanInfo) []string {
	seen := map[string]bool{}
	home := d.resolvePath(getHomeDir(d.exec))
	consider := func(p string, out *[]string) {
		if p == "" {
			return
		}
		// TCC: drop a project registered inside a macOS-protected tree (e.g.
		// ~/Documents) BEFORE resolvePath — EvalSymlinks stats every path
		// component, and statting inside the protected tree is itself what fires
		// the permission prompt we are avoiding. Canonicalize lexically only (no
		// EvalSymlinks/Stat) so the check touches nothing on disk. Registry,
		// node/python `extra`, and walk roots all flow through here, so this one
		// choke point covers every self-discovered project root.
		if d.skipper.WithinProtected(canonicalNoStat(p, home)) {
			return
		}
		resolved := d.resolvePath(p)
		if home != "" && resolved == home {
			return // home is never a project — its skill dirs are the global roots
		}
		if seen[resolved] {
			return
		}
		seen[resolved] = true
		if !d.exec.DirExists(resolved) {
			return // stale ~/.claude.json entry — skip silently
		}
		*out = append(*out, resolved)
	}
	// Tier 1: registry ∪ node/python roots (authoritative, sorted).
	var primary []string
	for _, p := range registry {
		consider(p, &primary)
	}
	for _, p := range extra {
		consider(p, &primary)
	}
	sort.Strings(primary)
	// Tier 2: home-walk candidates fill remaining capacity. The shared `seen` set
	// means a project already in tier 1 is not re-added, so tier 1 wins dedupe.
	var walk []string
	for _, p := range walkRoots {
		consider(p, &walk)
	}
	sort.Strings(walk)
	out := append(primary, walk...)
	if len(out) > maxProjects {
		info.Truncated = true
		d.addError(info, fmt.Sprintf("project roots truncated: %d discovered, capped at %d", len(out), maxProjects))
		out = out[:maxProjects]
	}
	return out
}

// enumerateRoot performs the depth-bounded recursive SKILL.md discovery
// under one root: a directory directly containing a SKILL.md (case-sensitive)
// is a skill (stop-at-skill), .git/node_modules are never descended, symlinked
// skill dirs are resolved, and the 2000-dir / 500-skill caps trip truncation.
func (d *SkillsDetector) enumerateRoot(ctx context.Context, root skillsRoot, info *model.AgentSkillScanInfo, memo map[string]*skillScan) []discoveredSkill {
	var records []discoveredSkill
	dirsVisited := 0
	rootTruncated := false

	var walk func(dir, rel string, depth int)
	walk = func(dir, rel string, depth int) {
		if rootTruncated || ctx.Err() != nil {
			return
		}
		dirsVisited++
		if dirsVisited > maxDirsPerRoot {
			rootTruncated = true
			info.Truncated = true
			d.addError(info, fmt.Sprintf("root %s: dir walk truncated at %d dirs", root.path, maxDirsPerRoot))
			return
		}

		entries, err := d.exec.ReadDir(dir)
		if err != nil {
			d.addError(info, fmt.Sprintf("read dir %s: %v", dir, err))
			return
		}

		// Stop-at-skill: if this dir (below the root) directly contains a
		// SKILL.md, it is a skill and its subdirs are its own files, not
		// separate skills.
		if depth > 0 {
			if mdName, ok := findSkillMD(entries); ok {
				if !d.emitSkill(ctx, &records, root, dir, rel, mdName, false, info, memo) {
					rootTruncated = true
				}
				return
			}
		}

		// Recurse into subdirectories (sorted for deterministic truncation).
		entMap := make(map[string]os.DirEntry, len(entries))
		for _, e := range entries {
			entMap[e.Name()] = e
		}
		for _, name := range sortedEntryNames(entries) {
			if rootTruncated || ctx.Err() != nil {
				return
			}
			if name == ".git" || name == "node_modules" {
				continue
			}
			if depth == 0 && root.excludeName != "" && name == root.excludeName {
				continue // codex .system carve-out
			}
			ent := entMap[name]
			childRel := name
			if rel != "" {
				childRel = rel + "/" + name
			}
			childDir := filepath.Join(dir, name)

			// Depth cap applies to the skill entry at this level, symlinked or
			// not: a symlinked skill dir at level >10 must be excluded exactly
			// as a regular dir at that level is (depth ≤10). Checked before
			// the symlink branch so both paths honor the same bound.
			if depth+1 > maxSkillWalkDepth {
				continue
			}

			// A Windows directory junction (what skills.sh creates there) is
			// reported by ReadDir as ModeIrregular with IsDir false; without
			// this it would be skipped as a plain file and the linking root's
			// association lost. Readlink reads a junction's target as it does
			// a symlink's, so both take the one link path.
			isSymlink := ent.Type()&os.ModeSymlink != 0
			isJunction := ent.Type()&os.ModeIrregular != 0 && d.exec.GOOS() == model.PlatformWindows
			if isSymlink || isJunction {
				d.handleSymlinkEntry(ctx, &records, root, childDir, childRel, isSymlink, info, memo, &rootTruncated)
				continue
			}
			if !ent.IsDir() {
				continue // a plain file directly under a dir is not a skill
			}
			walk(childDir, childRel, depth+1)
		}
	}

	walk(root.path, "", 0)
	return records
}

// handleSymlinkEntry resolves a linked directory entry — a symlink, or on
// Windows a directory junction (isSymlink false) — and if its target is a
// skill dir records it as a symlink shadow (the skills.sh layout), later folded
// into the physical skill's record by collapseSymlinkShadows. Links are never
// descended through — cycles and ~/ escapes are impossible.
//
// Linked targets are resolved and read through safepath, checking each link's
// destination before traversal. Normal shared links inside the user's home or
// declared project remain supported; unrelated external targets are refused.
func (d *SkillsDetector) handleSymlinkEntry(ctx context.Context, records *[]discoveredSkill, root skillsRoot, linkPath, rel string, isSymlink bool, info *model.AgentSkillScanInfo, memo map[string]*skillScan, rootTruncated *bool) {
	target, ok := linkTarget(d.exec, linkPath)
	if !ok {
		if isSymlink {
			d.addError(info, fmt.Sprintf("unreadable symlink %s", linkPath))
		}
		// An irregular entry whose target cannot be read is not a junction
		// (a socket, a device, a reparse point of another kind): not a skill,
		// not an error.
		return
	}
	if d.skipper.WithinProtected(target) {
		return
	}
	guarded := *d
	guarded.exec = d.exec.GuardedFiles([]string{getHomeDir(d.exec), root.path, root.projectPath}, func(p string) string {
		if d.skipper.WithinProtected(p) {
			return "tcc_protected"
		}
		return ""
	}, maxSkillMDReadBytes)
	resolved, err := guarded.exec.EvalSymlinks(target)
	if err != nil || resolved == "" {
		d.addError(info, fmt.Sprintf("dangling symlink %s: %v", linkPath, err))
		return
	}
	target = resolved
	if d.skipper.WithinProtected(target) {
		return
	}
	entries, err := guarded.exec.ReadDir(target)
	if err != nil {
		d.addError(info, fmt.Sprintf("read symlink target %s: %v", target, err))
		return
	}
	mdName, ok := findSkillMD(entries)
	if !ok {
		return // symlink to a non-skill dir — not descended
	}
	if !guarded.emitSkill(ctx, records, root, target, rel, mdName, true, info, memo) {
		*rootTruncated = true
	}
}

// linkTarget returns the absolute target a symlink or Windows junction
// stores, without following it. Relative targets are joined to the link's
// parent but never cleaned: a `..` after a symlinked component resolves
// through that link's target, so collapsing it lexically would name a
// different directory than EvalSymlinks reaches (the TCC guard cleans its own
// copy). Off Windows the target is taken literally (a backslash is an
// ordinary character there). On Windows the NT-namespace prefix junctions
// carry (`\??\`, `\\?\`) is dropped, and the volume-GUID, `UNC\` and
// `\\server\share` forms, which cannot be guarded lexically, are rejected. ok
// is false for a non-link and every rejected target.
func linkTarget(exec executor.Executor, linkPath string) (string, bool) {
	raw, err := exec.Readlink(linkPath)
	if err != nil || raw == "" {
		return "", false
	}
	if exec.GOOS() != model.PlatformWindows {
		if !path.IsAbs(raw) {
			raw = path.Dir(linkPath) + "/" + raw
		}
		return raw, true
	}
	stripped := strings.TrimPrefix(strings.TrimPrefix(raw, `\??\`), `\\?\`)
	switch {
	case strings.HasPrefix(stripped, `\\`), strings.HasPrefix(stripped, "//"),
		strings.HasPrefix(stripped, "Volume{"), strings.HasPrefix(stripped, `UNC\`), strings.HasPrefix(stripped, "GLOBALROOT"):
		return "", false
	case stripped != raw && !isAbsPath(stripped):
		return "", false // a namespace prefix on a relative spelling is not a path
	case !isAbsPath(stripped):
		stripped = joinPath(pathDir(linkPath), stripped)
	}
	return stripped, true
}

// emitSkill appends one discoveredSkill for a skill directory, applying the
// per-root 500-skill cap. dir is the resolved skill directory (the symlink
// target when isSymlink). Returns false when the per-root cap was hit (caller
// should stop enumerating this root).
func (d *SkillsDetector) emitSkill(ctx context.Context, records *[]discoveredSkill, root skillsRoot, dir, rel, mdName string, isSymlink bool, info *model.AgentSkillScanInfo, memo map[string]*skillScan) bool {
	// Per-root cap. records is this root's own accumulator — enumerateRoot returns
	// a fresh slice per call and every record it holds carries this root's source
	// + project_path — so its length is exactly the count emitted for this root;
	// no need to re-scan and filter it on every emit.
	if len(*records) >= maxSkillsPerRoot {
		info.Truncated = true
		d.addError(info, fmt.Sprintf("root %s: skills truncated at %d", root.path, maxSkillsPerRoot))
		return false
	}

	slug := path.Base(rel)
	mdPath := filepath.Join(dir, mdName)

	rec := model.AgentSkill{
		SkillSlug:    slug,
		SkillName:    slug,
		Agent:        root.agent,
		Source:       root.source,
		Scope:        root.scope,
		ProjectPath:  root.projectPath,
		SkillDirPath: dir,
		RootRelPath:  rel,
		SkillMDPath:  mdPath,
	}

	// Frontmatter + skill_md_hash + stat-only census, all memoized per resolved
	// dir path so a skill exposed through N symlinked roots is read, parsed, and
	// hashed exactly once. SKILL.md is read via the resolved path — the only file
	// the detector ever reads; no other file contents are read.
	resolvedDir := d.resolvePath(dir)
	scan, ok := memo[resolvedDir]
	if !ok {
		scan = &skillScan{
			meta:   d.parseSkillMD(filepath.Join(resolvedDir, mdName)),
			census: d.census(ctx, resolvedDir),
		}
		memo[resolvedDir] = scan
	}
	meta, census := scan.meta, scan.census

	rec.HasFrontmatter = meta.hasFrontmatter
	rec.FrontmatterError = meta.frontmatterError
	if meta.name != "" {
		rec.SkillName = meta.name
	}
	rec.Description = meta.description
	rec.Version = meta.version
	rec.License = meta.license
	rec.AllowedTools = meta.allowedTools
	rec.DisableModelInvocation = meta.disableModelInvoc
	rec.UserInvocableDisabled = meta.userInvocDisabled
	rec.ContextFork = meta.contextFork
	rec.ModelOverride = meta.modelOverride
	rec.HasHooks = meta.hasHooks
	rec.HasShellInjection = meta.hasShellInjection
	rec.SkillMDHash = meta.skillMDHash

	rec.FileCount = census.fileCount
	rec.CodeFileCount = census.codeFileCount
	rec.SymlinkCount = census.symlinkCount
	rec.TotalSizeBytes = census.totalSizeBytes
	rec.HasCode = census.codeFileCount > 0
	rec.HasPluginManifest = census.hasPluginManifest
	rec.LastModified = census.lastModified

	*records = append(*records, discoveredSkill{rec: rec, isSymlink: isSymlink, resolvedDir: resolvedDir})
	return true
}

// resolvePath resolves symlinks best-effort; on failure it returns the input
// unchanged (matching EvalSymlinks on a non-symlink).
func (d *SkillsDetector) resolvePath(p string) string {
	if resolved, err := d.exec.EvalSymlinks(p); err == nil && resolved != "" {
		return resolved
	}
	return p
}

// canonicalNoStat returns an absolute, ~-expanded, lexically-cleaned form of p
// with no filesystem access, so it is safe to hand to tcc.WithinProtected for a
// path that may live under a protected dir (statting it is what pops the
// dialog). Unlike resolvePath it never calls EvalSymlinks/Stat; filepath.Abs
// only consults os.Getwd. ~/.claude.json keys are normally absolute — the ~
// handling is defensive.
func canonicalNoStat(p, home string) string {
	if p == "~" {
		p = home
	} else if strings.HasPrefix(p, "~/") && home != "" {
		p = filepath.Join(home, p[2:])
	}
	if !filepath.IsAbs(p) {
		if abs, err := filepath.Abs(p); err == nil { // Abs does not stat p
			p = abs
		}
	}
	return filepath.Clean(p)
}

// addError appends a bounded scan error (≤50 entries, each ≤256 chars) so a
// hostile filename cannot balloon the payload via error strings.
func (d *SkillsDetector) addError(info *model.AgentSkillScanInfo, msg string) {
	if len(info.Errors) >= maxScanErrors {
		return
	}
	if len(msg) > maxScanErrorLen {
		msg = msg[:maxScanErrorLen]
	}
	info.Errors = append(info.Errors, msg)
}

// findSkillMD reports whether a regular file named exactly "SKILL.md" is
// directly present in entries (case-sensitive), returning that name.
// Discovery is a literal name compare over the directory listing — not an
// open() — so a case-insensitive filesystem does not rescue a lowercase
// skill.md (see anthropics/skills#314). A directory named "SKILL.md" never
// qualifies; only regular files do.
func findSkillMD(entries []os.DirEntry) (string, bool) {
	for _, e := range entries {
		// Only a regular file qualifies. e.Type() (not e.Info()) is authoritative:
		// os.ReadDir resolves DT_UNKNOWN so the type bits are reliable, and this one
		// check subsumes the dir/symlink skips while also rejecting a FIFO/socket/
		// device named SKILL.md — parseSkillMD's os.ReadFile would block forever on a
		// reader-less FIFO (no ctx), hanging the synchronous scan. Residual TOCTOU
		// (regular at check, swapped before read) is accepted; closing it needs a
		// ctx-aware / O_NONBLOCK open, out of scope here.
		if !e.Type().IsRegular() {
			continue
		}
		if e.Name() == "SKILL.md" {
			return e.Name(), true
		}
	}
	return "", false
}

// sortedEntryNames returns the entry names sorted in byte order, so both the
// walk order and any cap-driven truncation are deterministic regardless of the
// order ReadDir yields.
func sortedEntryNames(entries []os.DirEntry) []string {
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// collapseSymlinkShadows folds every symlink shadow of a physical skill into one
// record. skills.sh installs a skill once (e.g. ~/.agents/skills/foo) and
// symlinks it into each agent's own root, so enumeration emits one discoveredSkill
// per root, all resolving to the same physical dir. This groups by that resolved
// dir, keeps a canonical record (the real directory, else a deterministic pick),
// records the other roots' source labels in symlink_sources, and drops the
// shadows. Deterministic and order-independent (the final sort fixes output
// order regardless of map iteration).
func collapseSymlinkShadows(discovered []discoveredSkill) []model.AgentSkill {
	groups := map[string][]discoveredSkill{}
	var order []string
	for _, ds := range discovered {
		if _, ok := groups[ds.resolvedDir]; !ok {
			order = append(order, ds.resolvedDir)
		}
		groups[ds.resolvedDir] = append(groups[ds.resolvedDir], ds)
	}

	out := make([]model.AgentSkill, 0, len(groups))
	for _, key := range order {
		members := groups[key]
		canon := 0
		for i := 1; i < len(members); i++ {
			if betterCanonical(members[i], members[canon]) {
				canon = i
			}
		}
		rec := members[canon].rec

		// symlink_sources = the sorted, deduped sources of the other members,
		// pre-seeded with the canonical source so a member that shares it is never
		// echoed back — each entry is a distinct root symlinking into this dir.
		seen := map[string]bool{members[canon].rec.Source: true}
		var srcs []string
		for i, m := range members {
			if i == canon || seen[m.rec.Source] {
				continue
			}
			seen[m.rec.Source] = true
			srcs = append(srcs, m.rec.Source)
		}
		if len(srcs) > 0 {
			sort.Strings(srcs)
			rec.SymlinkSources = srcs
		}
		out = append(out, rec)
	}
	return out
}

// betterCanonical reports whether a should replace b as a collapse group's
// canonical record: the real (non-symlink) directory wins, then a fixed
// source/root order so the pick is stable when a group is all symlinks or two
// real dirs resolve to one physical dir (e.g. a bind mount).
func betterCanonical(a, b discoveredSkill) bool {
	if a.isSymlink != b.isSymlink {
		return !a.isSymlink // the real dir reached through its own root wins
	}
	if a.rec.Source != b.rec.Source {
		return a.rec.Source < b.rec.Source
	}
	return a.rec.RootRelPath < b.rec.RootRelPath
}

// sortSkills orders records by (source, project_path, skill_slug) for
// deterministic, diff-stable payloads.
func sortSkills(records []model.AgentSkill) {
	sort.SliceStable(records, func(i, j int) bool {
		a, b := records[i], records[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.ProjectPath != b.ProjectPath {
			return a.ProjectPath < b.ProjectPath
		}
		if a.SkillSlug != b.SkillSlug {
			return a.SkillSlug < b.SkillSlug
		}
		// Stable tiebreak so two records sharing the triple (e.g. symlink farm)
		// keep a fixed order across runs.
		return a.RootRelPath < b.RootRelPath
	})
}
