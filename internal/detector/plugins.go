package detector

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/safepath"
)

// Agent plugin inventory: shared identity, caps, guarded reads and component
// construction for the Claude Code and Codex adapters. Everything here is a
// filesystem read; no agent is ever executed.

const (
	agentPluginsSchemaVersion = 1
	pluginsPhaseBudget        = 60 * time.Second

	maxPluginContexts      = 32
	maxUsageSources        = 32
	maxMarketplaceObs      = 256
	maxPluginObs           = 1024
	maxComponentsPerPlugin = 256
	maxComponentsTotal     = 4096
	maxNewDefinitions      = 2000 // plugin skills/commands + standalone commands
	maxPluginMCPServers    = 2000
	maxUsageCounters       = 10000
	maxIDBytes             = 128
	maxNameBytes           = 512
	maxPathBytes           = 4096
	maxScopeErrors         = 20
	maxEnvelopeErrors      = 100
	maxSparsePaths         = 256
	maxAutoUpdatePrefs     = 64
	maxEnvelopeBytes       = 8 << 20
	maxComponentWalkDepth  = 6
	maxComponentDirs       = 500
	maxRecordedUses        = 1<<53 - 1
)

// pluginScan is the per-run state shared by both adapters: one observation
// time, the SKILL.md parse memo shared with the ordinary skill walk, and the
// envelope-wide budgets.
type pluginScan struct {
	d                  *SkillsDetector
	ctx                context.Context
	home               string
	goos               string
	now                time.Time
	projects           []string
	projectsIncomplete bool
	searchDirs         []string
	memo               map[string]*skillScan
	commands           map[string]commandMeta
	definitions        *int
	mcpServers         int
	components         int
	evidence           *pluginEvidence
	reads              map[string]pluginMetadataStamp
	sourceChanged      bool
}

// pluginEvidence is what the MCP reconciliation needs after the phase: the
// config files that became plugin components, and the covered subtrees the
// ordinary walker must not resurface as standalone servers.
type pluginEvidence struct {
	owned      map[string]bool
	suppressed []string
}

// nestedAttr is the owning-context attribution stamped on nested skill and MCP
// payloads.
type nestedAttr struct {
	agent, source, vendor, scope, projectPath string
}

// pluginRootScan is one plugin's component enumeration: its guarded executor,
// the selected root and how nested payloads are attributed.
type pluginRootScan struct {
	s    *pluginScan
	gd   *SkillsDetector // guarded copy of the detector
	p    *model.PluginObservation
	root string
	attr nestedAttr
}

// AgentVersions selects Claude Code and Codex versions from the AI CLI inventory.
func AgentVersions(tools []model.AITool) map[string]string {
	out := map[string]string{}
	for _, t := range tools {
		if (t.Name == model.AgentClaudeCode || t.Name == model.AgentCodex) && t.Version != "" {
			out[t.Name] = t.Version
		}
	}
	return out
}

// StripNestedMCPContent blanks the sanitized MCP bodies inside plugin
// components for the community output, which never carries config content.
func StripNestedMCPContent(scan *model.AgentPlugins) {
	if scan == nil {
		return
	}
	for i := range scan.Contexts {
		for j := range scan.Contexts[i].Plugins {
			for k := range scan.Contexts[i].Plugins[j].Components {
				if mcp := scan.Contexts[i].Plugins[j].Components[k].MCPConfig; mcp != nil {
					mcp.ConfigContentBase64 = ""
				}
			}
		}
	}
}

// SkillsResult carries the skills and plugin observations from one scan run.
type SkillsResult struct {
	Skills         []model.AgentSkill
	Info           *model.AgentSkillScanInfo
	Plugins        *model.AgentPlugins
	usage          *skillUsageObservations
	evidence       *pluginEvidence
	pendingPlugins *pluginScan
}

// DetectPlugins collects plugin metadata using the discovery state in result.
// A panic leaves plugin coverage unreported and preserves completed skill results.
func (d *SkillsDetector) DetectPlugins(ctx context.Context, result *SkillsResult) (err error) {
	if result.pendingPlugins == nil {
		return nil
	}
	s := result.pendingPlugins
	result.pendingPlugins = nil
	ctx, cancel := context.WithTimeout(ctx, pluginsPhaseBudget)
	defer cancel()
	s.ctx = ctx
	defer func() {
		if r := recover(); r != nil {
			result.Plugins, result.evidence = nil, nil
			err = fmt.Errorf("panic in plugins detect: %v", r)
		}
	}()
	s.now = time.Now()
	if d.now != nil {
		s.now = d.now()
	}
	var contexts []*model.AgentPluginContext
	for _, c := range []*model.AgentPluginContext{s.detectClaude(), s.detectCodex()} {
		if c != nil {
			// Missing projects can hide project settings and catalogs.
			if s.projectsIncomplete {
				degrade(&c.MarketplaceStatus, model.AgentScanStatusPartial)
				degrade(&c.InstallationStatus, model.AgentScanStatusPartial)
			}
			contexts = append(contexts, c)
		}
	}
	result.Plugins = s.finalizePluginScan(contexts)
	associateSkillUsage(result)
	result.evidence = s.evidence
	return nil
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

// inventoryHash is H(parts...): lowercase hex SHA-256 of the JSON array encoding.
func inventoryHash(parts ...string) string {
	b, _ := json.Marshal(parts)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hashPath is the hashing form of a device path: cleaned, slash-separated, and
// on Windows stripped of the extended prefix and case-folded. Display fields
// keep the observed spelling.
func (s *pluginScan) hashPath(p string) string {
	if p == "" {
		return ""
	}
	if s.goos == model.PlatformWindows {
		p = strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
		for _, prefix := range []string{"//?/", "/??/", "//./"} {
			if strings.HasPrefix(p, prefix) {
				p = p[len(prefix):]
				break
			}
		}
		if strings.HasPrefix(p, "unc/") {
			p = "//" + p[4:]
		}
	}
	unc := strings.HasPrefix(p, "//")
	p = path.Clean(p)
	if unc {
		p = "/" + p
	}
	return p
}

func cleanPluginPath(p string) string {
	if p == "" {
		return ""
	}
	if len(p) >= 7 && strings.HasPrefix(p, `\\?\`) && p[5] == ':' && p[6] == '\\' && ((p[4] >= 'A' && p[4] <= 'Z') || (p[4] >= 'a' && p[4] <= 'z')) {
		p = p[4:]
	}
	return filepath.Clean(p)
}

func (s *pluginScan) contextID(agent, configRoot, pluginRoot string) string {
	return "ctx_" + inventoryHash(agent, s.hashPath(configRoot), s.hashPath(pluginRoot))
}

func marketplaceID(contextID, name string) string {
	return "market_" + inventoryHash(contextID, name)
}

func (s *pluginScan) instanceID(contextID string, p *model.PluginObservation) string {
	var origin string
	switch p.InstallationKind {
	case model.PluginInstallMarketplace:
		origin = p.MarketplaceID
	case model.PluginInstallAccount:
		origin = p.RemotePluginID
		if origin == "" {
			origin = p.NativeID
		}
	case model.PluginInstallDirectory, model.PluginInstallSynced:
		origin = s.hashPath(p.SourcePath)
		if origin == "" {
			origin = s.hashPath(p.InstallPath)
		}
	default:
		origin = p.NativeID
	}
	return "inst_" + inventoryHash(contextID, p.NativeID, p.InstallationKind, p.Scope, s.hashPath(p.ProjectPath), origin)
}

func componentID(instanceID string, c model.PluginComponent) string {
	return "comp_" + inventoryHash(instanceID, c.Kind, c.RelativePath, c.DeclarationPointer, c.Name)
}

func (s *pluginScan) usageSourceID(agent, sourcePath string) string {
	return "usage_" + inventoryHash(agent, s.hashPath(sourcePath))
}

// ---------------------------------------------------------------------------
// Coverage and errors
// ---------------------------------------------------------------------------

func statusRank(st string) int {
	switch st {
	case model.AgentScanStatusPartial:
		return 1
	case model.AgentScanStatusUnsupported:
		return 2
	case model.AgentScanStatusError:
		return 3
	}
	return 0
}

// degrade lowers a coverage status; it never raises one.
func degrade(status *string, to string) {
	if statusRank(to) > statusRank(*status) {
		*status = to
	}
}

// scanError appends a bounded, code-only error. A path too long to carry is
// dropped from the error, never truncated into another path.
func scanError(list *[]model.AgentScanError, e model.AgentScanError) {
	if len(*list) >= maxScopeErrors {
		return
	}
	if len(e.SourcePath) > maxPathBytes {
		e.SourcePath = ""
	}
	*list = append(*list, e)
}

// readCode maps a guarded read failure onto a wire error code.
func readCode(err error) string {
	var ref *safepath.Refusal
	if errors.As(err, &ref) {
		switch ref.Reason {
		case safepath.ReasonOutsideRoots, safepath.ReasonSymlink, "tcc_protected":
			return model.AgentScanErrUnsafePath
		}
	}
	return model.AgentScanErrReadFailed
}

// ---------------------------------------------------------------------------
// Guarded filesystem primitives
// ---------------------------------------------------------------------------

// guarded builds a detector copy whose reads are confined to roots and refused
// inside TCC-protected trees. Metadata reads are capped at maxJSONConfigBytes.
func (s *pluginScan) guarded(roots ...string) *SkillsDetector {
	all := append([]string{s.home}, roots...)
	if s.goos == model.PlatformDarwin {
		for _, root := range roots {
			if strings.HasPrefix(root, "/etc/") {
				all = append(all, "/private"+root)
			}
		}
	}
	all = append(all, s.searchDirs...)
	all = append(all, s.projects...)
	gd := *s.d
	gd.exec = s.d.exec.GuardedFiles(all, func(p string) string {
		if s.d.skipper.WithinProtected(p) {
			return "tcc_protected"
		}
		return ""
	}, maxJSONConfigBytes)
	return &gd
}

// componentReader confines redirected component paths to the selected payload.
func (d *SkillsDetector) componentReader(root string) *SkillsDetector {
	gd := *d
	roots := []string{root}
	if resolved, err := d.exec.EvalSymlinks(root); err == nil && resolved != root {
		roots = append(roots, resolved)
	}
	gd.exec = d.exec.GuardedFiles(roots, func(p string) string {
		if d.skipper.WithinProtected(p) {
			return "tcc_protected"
		}
		return ""
	}, maxJSONConfigBytes)
	return &gd
}

// fileState classifies a path before it is read.
type fileState int

const (
	fileAbsent fileState = iota
	fileRegular
	fileDir
	fileOther
	fileRefused
)

func (s *pluginScan) stat(gd *SkillsDetector, p string) (fileState, os.FileInfo, error) {
	if s.ctx != nil && s.ctx.Err() != nil {
		return fileRefused, nil, s.ctx.Err()
	}
	if s.d.skipper.WithinProtected(p) {
		return fileRefused, nil, &safepath.Refusal{Reason: "tcc_protected"}
	}
	fi, err := gd.exec.Stat(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileAbsent, nil, nil
		}
		return fileRefused, nil, err
	}
	switch {
	case fi.IsDir():
		return fileDir, fi, nil
	case fi.Mode().IsRegular():
		return fileRegular, fi, nil
	}
	return fileOther, fi, nil
}

type pluginMetadataStamp struct {
	gd     *SkillsDetector
	hash   [32]byte
	absent bool
	code   string
}

func (s *pluginScan) snapshotChanged() bool {
	reads, changed := s.reads, s.sourceChanged
	s.reads = nil
	for _, p := range sortedMapKeys(reads) {
		before := reads[p]
		data, absent, code := s.readMetadata(before.gd, p)
		if before.hash != sha256.Sum256(data) || before.absent != absent || before.code != code {
			changed = true
		}
	}
	return changed
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// snapshotRetry captures counters, parsed definitions and attribution for retry.
func (s *pluginScan) snapshotRetry() func() {
	components, servers, definitions := s.components, s.mcpServers, *s.definitions
	memo, owned := maps.Clone(s.memo), maps.Clone(s.evidence.owned)
	commands := maps.Clone(s.commands)
	suppressed := append([]string(nil), s.evidence.suppressed...)
	return func() {
		s.components, s.mcpServers, *s.definitions = components, servers, definitions
		s.memo, s.evidence.owned = maps.Clone(memo), maps.Clone(owned)
		s.commands = maps.Clone(commands)
		s.evidence.suppressed = append([]string(nil), suppressed...)
	}
}

// readMetadata reads one JSON/TOML metadata file. absent is true when nothing
// exists at p; code is set when something exists but could not be read.
func (s *pluginScan) readMetadata(gd *SkillsDetector, p string) (data []byte, absent bool, code string) {
	defer func() {
		if s.reads == nil {
			return
		}
		stamp := pluginMetadataStamp{gd: gd, hash: sha256.Sum256(data), absent: absent, code: code}
		if previous, ok := s.reads[p]; ok && (previous.hash != stamp.hash || previous.absent != stamp.absent || previous.code != stamp.code) {
			s.sourceChanged = true
		}
		s.reads[p] = stamp
	}()
	st, fi, err := s.stat(gd, p)
	switch st {
	case fileAbsent:
		return nil, true, ""
	case fileRefused:
		return nil, false, readCode(err)
	case fileRegular:
		if fi.Size() > maxJSONConfigBytes {
			return nil, false, model.AgentScanErrLimitExceeded
		}
	default:
		return nil, false, model.AgentScanErrReadFailed
	}
	data, err = gd.exec.ReadFile(p)
	if err != nil {
		return nil, false, readCode(err)
	}
	if len(data) > maxJSONConfigBytes {
		return nil, false, model.AgentScanErrLimitExceeded
	}
	return data, false, ""
}

// readJSONObject decodes a metadata file into a string-keyed object.
func (s *pluginScan) readJSONObject(gd *SkillsDetector, p string) (obj map[string]json.RawMessage, absent bool, code string) {
	data, absent, code := s.readMetadata(gd, p)
	if absent || code != "" {
		return nil, absent, code
	}
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, false, model.AgentScanErrParseFailed
	}
	return obj, false, ""
}

// listDir lists a directory, or reports why it could not.
func (s *pluginScan) listDir(gd *SkillsDetector, dir string) ([]os.DirEntry, string) {
	if s.ctx != nil && s.ctx.Err() != nil {
		return nil, model.AgentScanErrReadFailed
	}
	if s.d.skipper.WithinProtected(dir) {
		return nil, model.AgentScanErrUnsafePath
	}
	entries, err := gd.exec.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ""
		}
		return nil, readCode(err)
	}
	return entries, ""
}

// dirExists is the tri-state directory probe: known present, known absent, or
// unknown because the guard refused the path.
func (s *pluginScan) dirExists(gd *SkillsDetector, dir string) *bool {
	st, _, _ := s.stat(gd, dir)
	switch st {
	case fileDir:
		return boolPtr(true)
	case fileAbsent, fileRegular, fileOther:
		return boolPtr(false)
	}
	return nil
}

func boolPtr(b bool) *bool { return &b }

// ---------------------------------------------------------------------------
// Value normalization
// ---------------------------------------------------------------------------

var scpLikeRE = regexp.MustCompile(`^[^/@:\s]+@([^/:\s]+):(.*)$`)

// sanitizeLocation strips userinfo, query and fragment from a URL, the user
// from an scp-style Git remote, and drops anything over the path cap rather
// than truncating it into another valid locator.
func sanitizeLocation(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxPathBytes {
		return ""
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil {
			return ""
		}
		u.User, u.RawQuery, u.Fragment, u.ForceQuery = nil, "", "", false
		return u.String()
	}
	if m := scpLikeRE.FindStringSubmatch(raw); m != nil {
		location, _, _ := strings.Cut(m[2], "?")
		location, _, _ = strings.Cut(location, "#")
		return m[1] + ":" + location
	}
	return raw
}

// sanitizeHomepage keeps only an HTTP(S) URL with no userinfo, query or fragment.
func sanitizeHomepage(raw string) string {
	loc := sanitizeLocation(raw)
	u, err := url.Parse(loc)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	return loc
}

// githubLocation expands an owner/repo shorthand to its HTTPS URL.
func githubLocation(repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return ""
	}
	if strings.Contains(repo, "://") || scpLikeRE.MatchString(repo) {
		return sanitizeLocation(repo)
	}
	return sanitizeLocation("https://github.com/" + strings.TrimPrefix(repo, "/"))
}

// boundedName returns s when it fits the name cap; identities are never truncated.
func boundedName(s string) (string, bool) {
	return s, s != "" && len(s) <= maxNameBytes
}

func validSource(loc *model.SourceLocator) bool {
	if loc == nil {
		return true
	}
	if len(loc.SparsePaths) > maxSparsePaths || len(loc.NativeKind) > maxNameBytes || len(loc.PackageName) > maxNameBytes {
		return false
	}
	for _, value := range []string{loc.Location, loc.Subdirectory, loc.RequestedRef, loc.RequestedSHA, loc.ResolvedRevision, loc.Integrity, loc.PackageVersion} {
		if len(value) > maxPathBytes {
			return false
		}
	}
	if loc.Subdirectory != "" {
		if _, ok := insideRoot(".", loc.Subdirectory); !ok {
			return false
		}
	}
	for _, value := range loc.SparsePaths {
		if len(value) > maxPathBytes {
			return false
		}
	}
	return true
}

// parseNativeTimeMs parses an RFC 3339 timestamp to Unix milliseconds. Invalid
// values are absent, never zero.
func parseNativeTimeMs(s string) *int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	ms := t.UnixMilli()
	if ms < 0 || ms > maxRecordedUses {
		return nil
	}
	return &ms
}

// relSlash returns p relative to root as a forward-slash path, or false when p
// escapes root. "." names the root itself.
func relSlash(root, p string) (string, bool) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// insideRoot joins a declared relative path under root, refusing traversal and
// absolute declarations. Declared paths are forward-slash.
func insideRoot(root, declared string) (string, bool) {
	declared = strings.TrimSpace(declared)
	if declared == "" || isAbsPath(declared) || strings.Contains(declared, `\`) {
		return "", false
	}
	clean := path.Clean(declared)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}
	if clean == "." {
		return root, true
	}
	return filepath.Join(root, filepath.FromSlash(clean)), true
}

// stringList accepts a JSON string or array of strings.
func stringList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		return many
	}
	return nil
}

func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func jsonBool(raw json.RawMessage) *bool {
	var b *bool
	if len(raw) > 0 && json.Unmarshal(raw, &b) == nil {
		return b
	}
	return nil
}

// nameField reads a display name from either a string or {"name": ...}.
func nameField(raw json.RawMessage) string {
	if s := jsonString(raw); s != "" {
		return s
	}
	var obj struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return obj.Name
	}
	return ""
}

// ---------------------------------------------------------------------------
// Components
// ---------------------------------------------------------------------------

// addComponent finalizes identity and callable names and appends c, honoring
// the per-plugin and envelope caps. An unboundable name or path rejects the
// component and marks the parent partial rather than truncating an identity.
func (r *pluginRootScan) addComponent(c model.PluginComponent) bool {
	p := r.p
	if len(c.DefinitionPath) > maxPathBytes || len(c.ResolvedDefinitionPath) > maxPathBytes || len(c.DeclarationPointer) > maxPathBytes || c.Name == "" || len(c.Name) > maxNameBytes || len(c.RelativePath) > maxPathBytes || c.RelativePath == "" || isAbsPath(c.RelativePath) || strings.Contains("/"+c.RelativePath+"/", "/../") {
		degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
		scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrUnsafePath, InstanceID: p.InstanceID, SourcePath: c.DefinitionPath})
		return false
	}
	for _, name := range c.CallableNames {
		if len(name) > maxNameBytes {
			degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
			return false
		}
	}
	c.ComponentID = componentID(p.InstanceID, c)
	for _, existing := range p.Components {
		if existing.ComponentID == c.ComponentID {
			return false
		}
	}
	if len(p.Components) >= maxComponentsPerPlugin || r.s.components >= maxComponentsTotal {
		degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
		scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, InstanceID: p.InstanceID})
		return false
	}
	if c.CallableNames == nil {
		c.CallableNames = []string{}
	}
	if c.Status == "" {
		c.Status = model.AgentScanStatusComplete
	}
	if c.Status == model.AgentScanStatusError || c.Status == model.AgentScanStatusPartial {
		degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
	}
	p.Components = append(p.Components, c)
	r.s.components++
	return true
}

// componentError records a definition that exists but could not be read.
func (r *pluginRootScan) componentError(c *model.PluginComponent, code string) {
	c.Status = model.AgentScanStatusError
	c.ComponentID = componentID(r.p.InstanceID, *c)
	scanError(&r.p.Errors, model.AgentScanError{Code: code, SourcePath: c.DefinitionPath, InstanceID: r.p.InstanceID, ComponentID: c.ComponentID})
}

// declared emits a descriptive component (agent, hook, lsp, app) with no payload.
func (r *pluginRootScan) declared(kind, name, rel, pointer, defPath, status string) {
	r.addComponent(model.PluginComponent{Kind: kind, Name: name, RelativePath: rel, DeclarationPointer: pointer, DefinitionPath: defPath, Status: status})
}

// takeDefinition charges one parsed definition against the shared budget.
func (r *pluginRootScan) takeDefinition() bool {
	if *r.s.definitions >= maxNewDefinitions {
		degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
		scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, InstanceID: r.p.InstanceID})
		return false
	}
	*r.s.definitions++
	return true
}

// skillComponent emits one skill directory as a component, parsing SKILL.md
// through the shared memo so a physical skill is read once per run.
func (r *pluginRootScan) skillComponent(dir, rel, name, callable string) {
	r.gd = r.gd.componentReader(r.root)
	c := model.PluginComponent{Kind: model.PluginComponentSkill, Name: name, RelativePath: path.Join(rel, "SKILL.md"), DefinitionPath: filepath.Join(dir, "SKILL.md")}
	if callable != "" {
		c.CallableNames = []string{callable}
	}
	entries, code := r.s.listDir(r.gd, dir)
	if code != "" {
		r.componentError(&c, code)
		r.addComponent(c)
		return
	}
	if !pluginSkillMD(entries) {
		r.componentError(&c, model.AgentScanErrReadFailed)
		r.addComponent(c)
		return
	}
	resolvedDir := dir
	if resolved, err := r.gd.exec.EvalSymlinks(dir); err == nil && resolved != "" {
		resolvedDir = resolved
		c.ResolvedDefinitionPath = filepath.Join(resolved, "SKILL.md")
	}
	if resolved, err := r.gd.exec.EvalSymlinks(c.DefinitionPath); err == nil {
		c.ResolvedDefinitionPath = resolved
	}
	if r.s.d.skipper.WithinProtected(resolvedDir) {
		r.componentError(&c, model.AgentScanErrUnsafePath)
		r.addComponent(c)
		return
	}
	scan, ok := r.s.memo[resolvedDir]
	if !ok {
		if !r.takeDefinition() {
			c.Status = model.AgentScanStatusPartial
			r.addComponent(c)
			return
		}
		scan = &skillScan{meta: r.gd.parseSkillMD(filepath.Join(resolvedDir, "SKILL.md")), census: r.gd.census(r.s.ctx, resolvedDir)}
		r.s.memo[resolvedDir] = scan
	}
	meta := scan.meta
	if meta.frontmatterError == "unreadable" || meta.frontmatterError == "file_too_large" || meta.frontmatterError == "invalid_yaml" {
		code := model.AgentScanErrReadFailed
		if meta.frontmatterError == "file_too_large" {
			code = model.AgentScanErrLimitExceeded
		}
		if meta.frontmatterError == "invalid_yaml" {
			code = model.AgentScanErrParseFailed
		}
		r.componentError(&c, code)
		r.addComponent(c)
		return
	}
	rec := model.AgentSkill{
		SkillSlug: name, SkillName: name, Agent: r.attr.agent, Source: r.attr.source,
		Scope: r.attr.scope, ProjectPath: r.attr.projectPath,
		SkillDirPath: resolvedDir, RootRelPath: path.Base(rel), SkillMDPath: c.DefinitionPath,
		DefinitionKind: model.AgentDefinitionSkill, DefinitionPath: c.DefinitionPath, CallableNames: c.CallableNames,
	}
	if rel == "." {
		rec.RootRelPath = ""
	}
	applySkillMeta(&rec, meta)
	c.Name = rec.SkillName
	if callable != "" {
		if rel != "." || strings.Contains(callable, ":") {
			c.CallableNames = []string{strings.TrimSuffix(callable, name) + rec.SkillName}
		}
		rec.CallableNames = c.CallableNames
	}
	applySkillCensus(&rec, scan.census)
	rec.DefinitionHash = meta.skillMDHash
	c.Skill = &rec
	r.addComponent(c)
}

// commandMetadata shares one bounded parse across every exposure of a command.
func (s *pluginScan) commandMetadata(gd *SkillsDetector, file string) commandMeta {
	key, err := gd.exec.EvalSymlinks(file)
	if err != nil {
		return commandMeta{readError: readCode(err)}
	}
	if key == "" {
		key = file
	}
	if meta, ok := s.commands[key]; ok {
		return meta
	}
	if *s.definitions >= maxNewDefinitions {
		return commandMeta{readError: model.AgentScanErrLimitExceeded}
	}
	*s.definitions++
	meta := gd.parseCommandMD(file)
	if s.commands == nil {
		s.commands = map[string]commandMeta{}
	}
	s.commands[key] = meta
	return meta
}

// commandComponent emits one legacy command Markdown file.
func (r *pluginRootScan) commandComponent(file, rel, name, callable string) {
	r.gd = r.gd.componentReader(r.root)
	c := model.PluginComponent{Kind: model.PluginComponentCommand, Name: name, RelativePath: rel, DefinitionPath: file, CallableNames: []string{callable}}
	meta := r.s.commandMetadata(r.gd, file)
	if meta.readError != "" || meta.frontmatterError == "invalid_yaml" {
		code := meta.readError
		if code == "" {
			code = model.AgentScanErrParseFailed
		}
		r.componentError(&c, code)
		r.addComponent(c)
		return
	}
	if resolved, err := r.gd.exec.EvalSymlinks(file); err == nil && resolved != "" {
		c.ResolvedDefinitionPath = resolved
	}
	c.Command = &model.AgentCommandDefinition{
		Name: name, DefinitionPath: file, DefinitionHash: meta.hash,
		Description: meta.description, Version: meta.version, License: meta.license, AllowedTools: meta.allowedTools,
		DisableModelInvocation: meta.disableModelInvoc, UserInvocableDisabled: meta.userInvocDisabled,
		HasHooks: meta.hasHooks, HasShellInjection: meta.hasShellInjection,
	}
	r.addComponent(c)
}

// mcpFileComponents projects one MCP JSON file into one component per declared
// server, each carrying only that server's allowlisted, redacted fields.
func (r *pluginRootScan) mcpFileComponents(file, rel string, required bool) {
	r.gd = r.gd.componentReader(r.root)
	data, absent, code := r.s.readMetadata(r.gd, file)
	if absent && !required {
		return
	}
	if absent {
		code = model.AgentScanErrReadFailed
	}
	if code == "" && r.p.ManifestFormat == model.PluginManifestPortable {
		if entries, err := r.gd.exec.ReadDir(filepath.Dir(file)); err == nil {
			for _, entry := range entries {
				if entry.Name() == filepath.Base(file) && entry.Type()&os.ModeSymlink != 0 {
					code = model.AgentScanErrUnsupportedSchema
				}
			}
		}
	}
	r.s.evidence.owned[filepath.Clean(file)] = true
	if code != "" {
		c := model.PluginComponent{Kind: model.PluginComponentMCP, Name: path.Base(rel), RelativePath: rel, DefinitionPath: file}
		r.componentError(&c, code)
		r.addComponent(c)
		return
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		c := model.PluginComponent{Kind: model.PluginComponentMCP, Name: path.Base(rel), RelativePath: rel, DefinitionPath: file}
		r.componentError(&c, model.AgentScanErrParseFailed)
		r.addComponent(c)
		return
	}
	if r.p.ManifestFormat == model.PluginManifestPortable && (len(doc) != 2 || jsonString(doc["$schema"]) != "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json" || doc["mcpServers"] == nil) {
		c := model.PluginComponent{Kind: model.PluginComponentMCP, Name: path.Base(rel), RelativePath: rel, DefinitionPath: file}
		r.componentError(&c, model.AgentScanErrUnsupportedSchema)
		r.addComponent(c)
		return
	}
	if servers, ok := doc["mcpServers"]; ok {
		r.mcpServerComponents(servers, rel, "/mcpServers", file)
	} else {
		r.mcpServerComponents(data, rel, "", file)
	}
}

// mcpInlineComponents projects an inline mcpServers object declared inside a
// manifest at pointer.
func (r *pluginRootScan) mcpInlineComponents(servers json.RawMessage, manifestRel, pointer, manifestPath string) {
	r.mcpServerComponents(servers, manifestRel, pointer, manifestPath)
}

func (r *pluginRootScan) mcpServerComponents(servers json.RawMessage, rel, pointer, configPath string) {
	resolvedPath, _ := r.gd.exec.EvalSymlinks(configPath)
	var declarations map[string]json.RawMessage
	if json.Unmarshal(servers, &declarations) != nil || declarations == nil {
		c := model.PluginComponent{Kind: model.PluginComponentMCP, Name: path.Base(rel), RelativePath: rel, DeclarationPointer: pointer, DefinitionPath: configPath}
		r.componentError(&c, model.AgentScanErrParseFailed)
		r.addComponent(c)
		return
	}
	for _, name := range sortedMapKeys(declarations) {
		if r.s.mcpServers >= maxPluginMCPServers || r.s.ctx != nil && r.s.ctx.Err() != nil {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, InstanceID: r.p.InstanceID, SourcePath: configPath})
			return
		}
		r.s.mcpServers++
		serverPointer := pointer
		if pointer != "" {
			serverPointer += "/" + strings.NewReplacer("~", "~0", "/", "~1").Replace(name)
		}
		if r.p.ManifestFormat == model.PluginManifestPortable {
			if code := r.portableMCPError(declarations[name]); code != "" {
				c := model.PluginComponent{Kind: model.PluginComponentMCP, Name: name, RelativePath: rel, DeclarationPointer: serverPointer, DefinitionPath: configPath}
				r.componentError(&c, code)
				r.addComponent(c)
				continue
			}
		}
		one, err := json.Marshal(map[string]json.RawMessage{name: declarations[name]})
		filtered := filterServerFields(one)
		if err != nil || filtered == nil || strings.TrimSpace(string(declarations[name])) == "null" {
			c := model.PluginComponent{Kind: model.PluginComponentMCP, Name: name, RelativePath: rel, DeclarationPointer: pointer, DefinitionPath: configPath}
			r.componentError(&c, model.AgentScanErrParseFailed)
			r.addComponent(c)
			continue
		}
		body, err := json.Marshal(map[string]any{"mcpServers": filtered})
		if err != nil {
			continue
		}
		c := model.PluginComponent{
			Kind: model.PluginComponentMCP, Name: name, RelativePath: rel, DeclarationPointer: serverPointer, DefinitionPath: configPath, ResolvedDefinitionPath: resolvedPath,
			MCPConfig: &model.MCPConfigEnterprise{ConfigSource: r.attr.source, ConfigPath: configPath, Vendor: r.attr.vendor, ConfigContentBase64: base64.StdEncoding.EncodeToString(body)},
		}
		r.addComponent(c)
	}
}

// skillDirs enumerates skill directories under dir: direct children when
// recursive is false, else a bounded stop-at-skill walk. Each returned path is
// a directory that directly contains a SKILL.md.
func (r *pluginRootScan) skillDirs(dir string, recursive bool) []string {
	r.gd = r.gd.componentReader(r.root)
	var out []string
	visited := 0
	var walk func(cur string, depth int)
	walk = func(cur string, depth int) {
		if r.s.ctx.Err() != nil || depth > maxComponentWalkDepth {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			return
		}
		visited++
		if visited > maxComponentDirs {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, InstanceID: r.p.InstanceID, SourcePath: dir})
			return
		}
		entries, code := r.s.listDir(r.gd, cur)
		if code != "" {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&r.p.Errors, model.AgentScanError{Code: code, InstanceID: r.p.InstanceID, SourcePath: cur})
			return
		}
		if depth > 0 {
			if pluginSkillMD(entries) {
				out = append(out, cur)
				return
			}
			if !recursive {
				return
			}
		}
		for _, name := range sortedEntryNames(entries) {
			ent := dirEntryByName(entries, name)
			if ent.Type()&os.ModeSymlink != 0 || !ent.IsDir() || name == ".git" || name == "node_modules" {
				continue
			}
			walk(filepath.Join(cur, name), depth+1)
		}
	}
	walk(dir, 0)
	return out
}

// Linked definitions are validated by the payload-confined reader before use.
func pluginSkillMD(entries []os.DirEntry) bool {
	for _, entry := range entries {
		if entry.Name() == "SKILL.md" && (entry.Type().IsRegular() || entry.Type()&os.ModeSymlink != 0) {
			return true
		}
	}
	return false
}

// markdownFiles lists *.md regular files under dir, bounded, never following
// symlinks. Paths are returned sorted.
func (r *pluginRootScan) markdownFiles(dir string) []string {
	r.gd = r.gd.componentReader(r.root)
	var out []string
	visited := 0
	var walk func(cur string, depth int)
	walk = func(cur string, depth int) {
		if r.s.ctx.Err() != nil || depth > maxComponentWalkDepth {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			return
		}
		visited++
		if visited > maxComponentDirs {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&r.p.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, InstanceID: r.p.InstanceID, SourcePath: dir})
			return
		}
		entries, code := r.s.listDir(r.gd, cur)
		if code != "" {
			degrade(&r.p.ComponentStatus, model.AgentScanStatusPartial)
			scanError(&r.p.Errors, model.AgentScanError{Code: code, InstanceID: r.p.InstanceID, SourcePath: cur})
			return
		}
		for _, name := range sortedEntryNames(entries) {
			ent := dirEntryByName(entries, name)
			switch {
			case ent.Type()&os.ModeSymlink != 0:
			case ent.IsDir():
				walk(filepath.Join(cur, name), depth+1)
			case ent.Type().IsRegular() && strings.HasSuffix(name, ".md"):
				out = append(out, filepath.Join(cur, name))
			}
		}
	}
	walk(dir, 0)
	return out
}

func dirEntryByName(entries []os.DirEntry, name string) os.DirEntry {
	for _, e := range entries {
		if e.Name() == name {
			return e
		}
	}
	return nil
}

// commandCallable derives the slash name from a command file's path below its
// commands root: commands/deploy.md → deploy, commands/frontend/component.md →
// frontend:component.
func commandCallable(rel string) string {
	rel = strings.TrimSuffix(filepath.ToSlash(rel), ".md")
	return strings.ReplaceAll(rel, "/", ":")
}

// applySkillMeta copies parsed frontmatter onto a wire record (shared with the
// ordinary skill walk).
func applySkillMeta(rec *model.AgentSkill, meta skillMeta) {
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
}

func applySkillCensus(rec *model.AgentSkill, census *skillCensus) {
	rec.FileCount = census.fileCount
	rec.CodeFileCount = census.codeFileCount
	rec.SymlinkCount = census.symlinkCount
	rec.TotalSizeBytes = census.totalSizeBytes
	rec.HasCode = census.codeFileCount > 0
	rec.HasPluginManifest = census.hasPluginManifest
	rec.LastModified = census.lastModified
}

// nestedScope maps a plugin scope to the skill scope vocabulary.
func nestedScope(pluginScope string) string {
	switch pluginScope {
	case model.PluginScopeUser:
		return "global"
	case model.PluginScopeProject, model.PluginScopeLocal:
		return "project"
	case model.PluginScopeSystem:
		return "system"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Plugin observations
// ---------------------------------------------------------------------------

// newPlugin returns an observation with every required array non-nil.
func newPlugin(nativeID, name, kind, scope string) *model.PluginObservation {
	return &model.PluginObservation{
		NativeID: nativeID, Name: name, InstallationKind: kind, Scope: scope,
		ComponentStatus: model.AgentScanStatusComplete,
		Enablement:      []model.EnablementObservation{},
		Components:      []model.PluginComponent{},
		Errors:          []model.AgentScanError{},
	}
}

// addPlugin assigns the instance identity and appends p to the context. Two
// records colliding on one instance ID make the context partial; the first is retained.
func (s *pluginScan) addPlugin(c *model.AgentPluginContext, p *model.PluginObservation) bool {
	if _, ok := boundedName(p.NativeID); !ok || len(p.NativeID) > maxIDBytes || p.Name == "" || len(p.Name) > maxNameBytes || len(p.RemotePluginID) > maxIDBytes {
		degrade(&c.InstallationStatus, model.AgentScanStatusPartial)
		scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: p.InstallPath})
		return false
	}
	for _, path := range []string{p.InstallPath, p.SourcePath, p.ManifestPath, p.ProjectPath} {
		if len(path) > maxPathBytes || path != "" && !isAbsPath(path) {
			degrade(&c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded})
			return false
		}
	}
	if (p.Scope == model.PluginScopeProject || p.Scope == model.PluginScopeLocal) && p.ProjectPath == "" {
		degrade(&c.InstallationStatus, model.AgentScanStatusPartial)
		scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, SourcePath: p.InstallPath})
		return false
	}
	p.InstanceID = s.instanceID(c.ContextID, p)
	for i := range c.Plugins {
		if c.Plugins[i].InstanceID == p.InstanceID {
			degrade(&c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrParseFailed, InstanceID: p.InstanceID, SourcePath: p.InstallPath})
			return false
		}
	}
	c.Plugins = append(c.Plugins, *p)
	return true
}

// newContext returns a context with identity and non-nil arrays.
func (s *pluginScan) newContext(agent, configRoot, pluginRoot string) *model.AgentPluginContext {
	return &model.AgentPluginContext{
		ContextID: s.contextID(agent, configRoot, pluginRoot), Agent: agent, AgentVersion: s.d.agentVersions[agent],
		ConfigRoot: cleanPluginPath(configRoot), PluginRoot: cleanPluginPath(pluginRoot),
		MarketplaceStatus: model.AgentScanStatusComplete, InstallationStatus: model.AgentScanStatusComplete,
		Marketplaces: []model.MarketplaceObservation{}, Plugins: []model.PluginObservation{}, Errors: []model.AgentScanError{},
	}
}

// unresolvedContext reports a configured root this process cannot inspect.
func (s *pluginScan) unresolvedContext(agent, configRoot, pluginRoot string) *model.AgentPluginContext {
	c := s.newContext(agent, configRoot, pluginRoot)
	c.MarketplaceStatus, c.InstallationStatus = model.AgentScanStatusError, model.AgentScanStatusError
	scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrRootUnresolved, SourcePath: configRoot})
	return c
}

// ---------------------------------------------------------------------------
// Envelope assembly
// ---------------------------------------------------------------------------

// finalizePluginScan sorts every list, applies the report-wide caps and the
// envelope byte budget, and returns nil when nothing survives.
func (s *pluginScan) finalizePluginScan(contexts []*model.AgentPluginContext) *model.AgentPlugins {
	if len(contexts) == 0 {
		return nil
	}
	sort.SliceStable(contexts, func(i, j int) bool {
		a, b := contexts[i], contexts[j]
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		if a.ConfigRoot != b.ConfigRoot {
			return a.ConfigRoot < b.ConfigRoot
		}
		return a.PluginRoot < b.PluginRoot
	})
	if len(contexts) > maxPluginContexts {
		contexts = contexts[:maxPluginContexts] // omitted contexts are unreported, never "removed"
	}
	scan := &model.AgentPlugins{SchemaVersion: agentPluginsSchemaVersion, CollectedAtMs: s.now.UnixMilli()}
	markets, plugins, errs := 0, 0, 0
	for _, c := range contexts {
		if !isAbsPath(c.ConfigRoot) || !isAbsPath(c.PluginRoot) || len(c.ConfigRoot) > maxPathBytes || len(c.PluginRoot) > maxPathBytes {
			continue
		}
		validMarkets := c.Marketplaces[:0]
		for _, m := range c.Marketplaces {
			if m.Name == "" || len(m.Name) > maxNameBytes {
				degrade(&c.MarketplaceStatus, model.AgentScanStatusPartial)
				scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded})
				continue
			}
			if !validSource(m.Source) || len(m.CatalogPath) > maxPathBytes || len(m.Revision) > maxPathBytes {
				m.Source, m.CatalogPath, m.Revision = nil, "", ""
				degrade(&c.MarketplaceStatus, model.AgentScanStatusPartial)
				scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded})
			}
			validMarkets = append(validMarkets, m)
		}
		c.Marketplaces = validMarkets
		sort.SliceStable(c.Marketplaces, func(i, j int) bool { return c.Marketplaces[i].Name < c.Marketplaces[j].Name })
		sort.SliceStable(c.Plugins, func(i, j int) bool {
			a, b := c.Plugins[i], c.Plugins[j]
			if a.NativeID != b.NativeID {
				return a.NativeID < b.NativeID
			}
			if a.Scope != b.Scope {
				return a.Scope < b.Scope
			}
			return a.ProjectPath < b.ProjectPath
		})
		if markets+len(c.Marketplaces) > maxMarketplaceObs {
			c.Marketplaces = c.Marketplaces[:max(0, maxMarketplaceObs-markets)]
			degrade(&c.MarketplaceStatus, model.AgentScanStatusPartial)
			scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: c.PluginRoot})
		}
		markets += len(c.Marketplaces)
		marketIDs := map[string]bool{}
		for _, m := range c.Marketplaces {
			marketIDs[m.MarketplaceID] = true
		}
		kept := c.Plugins[:0]
		for _, p := range c.Plugins {
			if p.MarketplaceID != "" && !marketIDs[p.MarketplaceID] {
				degrade(&c.InstallationStatus, model.AgentScanStatusPartial)
				continue
			}
			kept = append(kept, p)
		}
		c.Plugins = kept
		if plugins+len(c.Plugins) > maxPluginObs {
			c.Plugins = c.Plugins[:max(0, maxPluginObs-plugins)]
			degrade(&c.InstallationStatus, model.AgentScanStatusPartial)
			scanError(&c.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, SourcePath: c.PluginRoot})
		}
		plugins += len(c.Plugins)
		errs = capErrors(&c.Errors, errs)
		for i := range c.Plugins {
			p := &c.Plugins[i]
			invalid := false
			for _, field := range []*string{&p.ManifestName, &p.Publisher} {
				if len(*field) > maxNameBytes {
					*field = ""
					invalid = true
				}
			}
			for _, field := range []*string{&p.ManifestPath, &p.ManifestVersion, &p.CacheVersion, &p.Homepage} {
				if len(*field) > maxPathBytes {
					*field = ""
					invalid = true
				}
			}
			if !validSource(p.Source) {
				p.Source = nil
				invalid = true
			}
			if invalid {
				degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
				scanError(&p.Errors, model.AgentScanError{Code: model.AgentScanErrLimitExceeded, InstanceID: p.InstanceID})
			}
			sort.SliceStable(p.Components, func(i, j int) bool { return p.Components[i].ComponentID < p.Components[j].ComponentID })
			errs = capErrors(&p.Errors, errs)
		}
		scan.Contexts = append(scan.Contexts, *c)
	}
	if len(scan.Contexts) == 0 {
		return nil
	}
	if size := encodedSize(scan); size > maxEnvelopeBytes {
		for i := range scan.Contexts {
			for j := range scan.Contexts[i].Plugins {
				p := &scan.Contexts[i].Plugins[j]
				p.Components = []model.PluginComponent{}
				degrade(&p.ComponentStatus, model.AgentScanStatusPartial)
			}
		}
		if encodedSize(scan) > maxEnvelopeBytes {
			return nil
		}
	}
	return scan
}

// capErrors trims list to the envelope-wide error budget; used is the count
// already spent.
func capErrors(list *[]model.AgentScanError, used int) int {
	room := max(0, maxEnvelopeErrors-used)
	if len(*list) > room {
		*list = (*list)[:room]
	}
	return used + len(*list)
}

func encodedSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return maxEnvelopeBytes + 1
	}
	return len(b)
}

// ---------------------------------------------------------------------------
// MCP reconciliation
// ---------------------------------------------------------------------------

// representedMCPFiles contains files whose complete server declarations remain
// in the final plugin report.
func (r SkillsResult) representedMCPFiles() map[string]bool {
	files := map[string]bool{}
	if r.Plugins == nil {
		return files
	}
	for _, context := range r.Plugins.Contexts {
		for _, plugin := range context.Plugins {
			if plugin.ComponentStatus != model.AgentScanStatusComplete {
				continue
			}
			for _, component := range plugin.Components {
				if component.Kind == model.PluginComponentMCP && component.Status == model.AgentScanStatusComplete && component.MCPConfig != nil {
					files[filepath.Clean(component.DefinitionPath)] = true
				}
			}
		}
	}
	return files
}

// replacesMCPConfig suppresses walker findings represented by plugin components
// and vendored examples under plugin trees. Explicit configurations remain independent.
func (r SkillsResult) replacesMCPConfig(source, p string, represented map[string]bool) bool {
	if r.evidence == nil {
		return false
	}
	if source == "project_mcp" {
		return false
	}
	for _, spec := range mcpConfigDefinitions {
		if source == spec.SourceName {
			return false
		}
	}
	c := filepath.Clean(p)
	if r.evidence.owned[c] {
		return represented[c]
	}
	for _, prefix := range r.evidence.suppressed {
		if c == prefix || strings.HasPrefix(c, prefix+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ReconcilePluginMCP replaces plugin-classified walker findings without removing
// independently configured suppliers. Uncovered paths keep their classification.
func (r SkillsResult) ReconcilePluginMCP(configs []model.MCPConfigEnterprise) []model.MCPConfigEnterprise {
	if r.evidence == nil {
		return configs
	}
	represented := r.representedMCPFiles()
	out := make([]model.MCPConfigEnterprise, 0, len(configs))
	for _, c := range configs {
		if !r.replacesMCPConfig(c.ConfigSource, c.ConfigPath, represented) {
			out = append(out, c)
		}
	}
	return out
}

// ReconcilePluginMCPCommunity is ReconcilePluginMCP for the community shape.
func (r SkillsResult) ReconcilePluginMCPCommunity(configs []model.MCPConfig) []model.MCPConfig {
	if r.evidence == nil {
		return configs
	}
	represented := r.representedMCPFiles()
	out := make([]model.MCPConfig, 0, len(configs))
	for _, c := range configs {
		if !r.replacesMCPConfig(c.ConfigSource, c.ConfigPath, represented) {
			out = append(out, c)
		}
	}
	return out
}

// newPluginEvidence returns an empty evidence set.
func newPluginEvidence() *pluginEvidence {
	return &pluginEvidence{owned: map[string]bool{}}
}

// suppress records a covered subtree.
func (e *pluginEvidence) suppress(dirs ...string) {
	for _, d := range dirs {
		if d != "" {
			e.suppressed = append(e.suppressed, filepath.Clean(d))
		}
	}
}
