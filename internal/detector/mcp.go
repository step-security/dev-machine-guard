package detector

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"
	"github.com/tailscale/hujson"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
	"github.com/step-security/dev-machine-guard/internal/tcc"
)

type mcpConfigSpec struct {
	SourceName      string
	ConfigPath      string // macOS/Unix path (~/... expanded)
	WinConfigPath   string // Windows path (%ENVVAR%/... expanded); empty means same as ConfigPath
	LinuxConfigPath string // Linux path (~/... expanded); empty means same as ConfigPath
	Vendor          string
}

var mcpConfigDefinitions = []mcpConfigSpec{
	{"claude_desktop", "~/Library/Application Support/Claude/claude_desktop_config.json", "%APPDATA%/Claude/claude_desktop_config.json", "~/.config/Claude/claude_desktop_config.json", "Anthropic"},
	{"claude_code", "~/.claude/settings.json", "", "", "Anthropic"},
	{"claude_code", "~/.claude.json", "", "", "Anthropic"},
	{"cursor", "~/.cursor/mcp.json", "", "", "Cursor"},
	{"windsurf", "~/.codeium/windsurf/mcp_config.json", "", "", "Codeium"},
	{"antigravity", "~/.gemini/antigravity/mcp_config.json", "", "", "Google"},
	{"zed", "~/.config/zed/settings.json", "", "", "Zed"},
	{"open_interpreter", "~/.config/open-interpreter/config.yaml", "", "", "OpenSource"},
	{"codex", "~/.codex/config.toml", "", "", "OpenAI"},
	{"copilot", "~/.copilot/mcp-config.json", "", "", "GitHub"},
	// VS Code and VS Code-based editors keep user-level MCP servers in
	// <app-config>/User/mcp.json. These are targeted reads; on macOS the path
	// is under ~/Library, which the discovery walk deliberately never enters.
	{"vscode", "~/Library/Application Support/Code/User/mcp.json", "%APPDATA%/Code/User/mcp.json", "~/.config/Code/User/mcp.json", "Microsoft"},
	{"vscode_insiders", "~/Library/Application Support/Code - Insiders/User/mcp.json", "%APPDATA%/Code - Insiders/User/mcp.json", "~/.config/Code - Insiders/User/mcp.json", "Microsoft"},
	{"cursor_user", "~/Library/Application Support/Cursor/User/mcp.json", "%APPDATA%/Cursor/User/mcp.json", "~/.config/Cursor/User/mcp.json", "Cursor"},
	{"windsurf_user", "~/Library/Application Support/Windsurf/User/mcp.json", "%APPDATA%/Windsurf/User/mcp.json", "~/.config/Windsurf/User/mcp.json", "Codeium"},
	{"vscodium", "~/Library/Application Support/VSCodium/User/mcp.json", "%APPDATA%/VSCodium/User/mcp.json", "~/.config/VSCodium/User/mcp.json", "VSCodium"},
	// OpenCode uses the same ~/.config/opencode layout on every platform, so the
	// Windows and Linux fields stay empty and resolveConfigPath expands
	// ConfigPath against the resolved home. Both spellings are accepted by the
	// tool, so both are listed.
	{"opencode", "~/.config/opencode/opencode.json", "", "", "OpenCode"},
	{"opencode", "~/.config/opencode/opencode.jsonc", "", "", "OpenCode"},
}

// MCPDetector collects MCP configuration files.
type MCPDetector struct {
	exec    executor.Executor
	skipper *tcc.Skipper
	piEnv   executor.Executor
	piDir   string // Pi's agent directory, resolved during discovery
}

func NewMCPDetector(exec executor.Executor) *MCPDetector {
	return &MCPDetector{exec: exec}
}

// WithSkipper attaches a TCC skipper so the discovery walk skips
// macOS-protected directories. A nil skipper is a no-op. Returns the detector
// for chaining.
func (d *MCPDetector) WithSkipper(s *tcc.Skipper) *MCPDetector {
	d.skipper = s
	return d
}

// WithPiEnvironment resolves Pi's agent directory from exec's environment,
// which can see the scanned user's PI_CODING_AGENT_DIR when this process
// cannot. Other sources keep the detector's own executor.
func (d *MCPDetector) WithPiEnvironment(exec executor.Executor) *MCPDetector {
	d.piEnv = exec
	return d
}

// piRoot is Pi's agent directory, or its default when an override cannot be
// resolved.
func (d *MCPDetector) piRoot(homeDir string) string {
	env := d.piEnv
	if env == nil {
		env = d.exec
	}
	root, _ := piAgentRoot(env, homeDir)
	return root
}

// Detect returns the MCP config locations found on the host as community-mode
// MCPConfig structs (path, source, and vendor only). It does not read config
// content — DetectEnterprise does that. The enterprise parameter is unused and
// kept only for call-site compatibility.
func (d *MCPDetector) Detect(ctx context.Context, userIdentity string, searchDirs []string, enterprise bool) []model.MCPConfig {
	homeDir := getHomeDir(d.exec)
	var results []model.MCPConfig
	for _, loc := range d.allConfigLocations(ctx, homeDir, searchDirs) {
		results = append(results, model.MCPConfig{
			ConfigSource: loc.SourceName,
			ConfigPath:   loc.ConfigPath,
			Vendor:       loc.Vendor,
		})
	}
	return results
}

// DetectEnterprise returns enterprise-mode MCP configs with base64 content.
func (d *MCPDetector) DetectEnterprise(ctx context.Context, searchDirs []string) []model.MCPConfigEnterprise {
	homeDir := getHomeDir(d.exec)
	var results []model.MCPConfigEnterprise

	for _, loc := range d.allConfigLocations(ctx, homeDir, searchDirs) {
		reader := d.exec
		if loc.SourceName == "codex" || loc.SourceName == model.AgentCopilot || loc.SourceName == "pi" || loc.SourceName == "pi_project" || isPiMCPPath(loc.ConfigPath, d.piDir) || isCopilotProjectMCP(loc.ConfigPath) {
			roots := []string{filepath.Dir(loc.ConfigPath)}
			if isCopilotProjectMCP(loc.ConfigPath) {
				project := filepath.Dir(loc.ConfigPath)
				if filepath.Base(project) == ".github" {
					project = filepath.Dir(project)
				}
				roots = append(roots, homeDir, project)
				roots = append(roots, searchDirs...)
			}
			reader = reader.GuardedFiles(roots, func(path string) string {
				if d.skipper.WithinProtected(path) {
					return "tcc_protected"
				}
				return ""
			}, maxJSONConfigBytes)
		}
		content, err := reader.ReadFile(loc.ConfigPath)
		if err != nil || len(content) == 0 {
			continue
		}

		// Extract only MCP-relevant fields from supported formats.
		// If filtering fails, omit content
		// to avoid leaking secrets like env vars and auth headers.
		var contentBase64 string
		if filtered, ok := d.filterMCPContent(loc.SourceName, loc.ConfigPath, content); ok {
			contentBase64 = base64.StdEncoding.EncodeToString(filtered)
		}

		results = append(results, model.MCPConfigEnterprise{
			ConfigSource:        loc.SourceName,
			ConfigPath:          loc.ConfigPath,
			Vendor:              loc.Vendor,
			ConfigContentBase64: contentBase64,
		})
	}

	return results
}

// discoverProjectMCPConfigs finds .mcp.json files in Claude Code's recorded projects.
func (d *MCPDetector) discoverProjectMCPConfigs() []mcpConfigSpec {
	var specs []mcpConfigSpec
	seen := make(map[string]bool)

	for _, projectPath := range discoverClaudeProjects(d.exec) {
		mcpPath := filepath.Join(projectPath, ".mcp.json")
		if seen[mcpPath] {
			continue
		}
		seen[mcpPath] = true

		if !d.exec.FileExists(mcpPath) {
			continue
		}

		specs = append(specs, mcpConfigSpec{
			SourceName: "project_mcp",
			ConfigPath: mcpPath,
			Vendor:     "Project",
		})
	}

	return specs
}

// resolveConfigPath returns the appropriate config path for the current platform.
func (d *MCPDetector) resolveConfigPath(spec mcpConfigSpec, homeDir string) string {
	if spec.SourceName == model.AgentCopilot {
		return filepath.Join(copilotConfigRoot(d.exec, homeDir), "mcp-config.json")
	}
	if spec.SourceName == "codex" {
		if root := d.exec.Getenv("CODEX_HOME"); filepath.IsAbs(root) {
			return filepath.Join(root, "config.toml")
		}
	}
	if d.exec.GOOS() == model.PlatformWindows && spec.WinConfigPath != "" {
		return resolveEnvPath(d.exec, spec.WinConfigPath)
	}
	if d.exec.GOOS() != model.PlatformDarwin && spec.LinuxConfigPath != "" {
		return expandTilde(spec.LinuxConfigPath, homeDir)
	}
	return expandTilde(spec.ConfigPath, homeDir)
}

// filterMCPContent rebuilds a config file's MCP servers from public identities
// and presence placeholders. Returns the rebuilt content and true on success,
// or nil and false when the file cannot be read as a known shape, so raw
// content is never the fallback.
func (d *MCPDetector) filterMCPContent(sourceName, configPath string, content []byte) ([]byte, bool) {
	if sourceName == "codex" && strings.HasSuffix(configPath, ".toml") {
		var config struct {
			Servers map[string]map[string]any `toml:"mcp_servers"`
		}
		if toml.Unmarshal(content, &config) != nil || config.Servers == nil {
			return nil, false
		}
		var servers mcpProjection
		for _, server := range config.Servers {
			servers.add(server)
		}
		out, err := toml.Marshal(map[string]any{"mcp_servers": servers.servers()})
		return out, err == nil
	}
	if !strings.HasSuffix(configPath, ".json") && !strings.HasSuffix(configPath, ".jsonc") {
		return nil, false // Non-JSON formats cannot be safely filtered
	}

	if sourceName == model.AgentCopilot || sourceName == "copilot_project" {
		return filterCopilotMCP(content, sourceName != model.AgentCopilot)
	}

	// Pi's own files may start with a BOM and carry per-server enabled flags;
	// walked copies keep their label but get the same filter.
	if (sourceName == "pi" || sourceName == "pi_project" || sourceName == "discovered_mcp") && isPiMCPPath(configPath, d.piDir) {
		return filterPiMCP(content)
	}

	jsonInput := content

	// Strip JSONC comments for Zed
	if sourceName == "zed" {
		jsonInput = stripJSONCComments(jsonInput)
	}

	// OpenCode accepts JSONC under either spelling, and its own documented
	// examples carry trailing commas as well as comments. stripJSONCComments
	// removes the comments but leaves the commas, which json.Unmarshal then
	// rejects — dropping the content and losing the servers. hujson handles
	// both, and is already this repo's front door for real-world JSONC.
	if isOpenCodeConfigPath(configPath) || isCopilotProjectMCP(configPath) {
		standard, err := hujson.Standardize(jsonInput)
		if err != nil {
			return nil, false
		}
		jsonInput = standard
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(jsonInput, &raw); err != nil {
		return nil, false // Can't parse; don't return raw content
	}

	if isCopilotProjectMCP(configPath) && raw["mcpServers"] == nil && raw["context_servers"] == nil && raw["servers"] == nil && raw["mcp"] == nil {
		return filterCopilotMCP(jsonInput, true)
	}

	var servers mcpProjection
	if !servers.addContainers(raw) {
		return nil, false // No MCP servers found
	}
	return servers.json()
}

// isOpenCodeConfigPath reports whether a path is an OpenCode config, in either
// spelling. It tests the basename rather than the whole path on purpose: a
// substring test would relabel an ordinary .mcp.json as OpenCode merely because
// some ancestor directory is named "opencode" — a checkout of the tool itself,
// say — while claiming nothing the basename does not already name.
func isOpenCodeConfigPath(configPath string) bool {
	switch strings.ToLower(filepath.Base(configPath)) {
	case "opencode.json", "opencode.jsonc":
		return true
	}
	return false
}

// Placeholders stand for declarations the snapshot does not identify. They
// mark that a local or remote server is configured; the command is never run
// and the reserved .invalid host never resolves.
const (
	mcpUnidentifiedLocal  = "stepsecurity-unidentified-mcp-local"
	mcpUnidentifiedRemote = "https://unidentified-mcp.invalid"
)

// mcpRegistrySnapshot lists the public package, image and endpoint identities
// of the official MCP registry at the time it was fetched. It is refreshed with
// releases, never at scan or build time.
//
//go:embed builtin/mcp_registry.json
var mcpRegistrySnapshot []byte

// mcpRegistry maps the normalized form of each snapshot identity to the
// snapshot's own spelling, the only identity text that is ever emitted.
type mcpRegistry struct {
	npm, pypi, oci, remote map[string]string
}

// loadMCPRegistry parses the snapshot once. A snapshot that does not parse
// identifies nothing, so every server falls back to a placeholder.
var loadMCPRegistry = sync.OnceValue(func() mcpRegistry {
	return parseMCPRegistry(mcpRegistrySnapshot)
})

func parseMCPRegistry(data []byte) mcpRegistry {
	var doc struct {
		NPM    []string `json:"npm_packages"`
		PyPI   []string `json:"pypi_packages"`
		OCI    []string `json:"oci_images"`
		Remote []string `json:"remote_urls"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return mcpRegistry{}
	}
	index := func(ids []string, normalize func(string) string) map[string]string {
		out := make(map[string]string, len(ids))
		for _, id := range ids {
			if key := normalize(id); key != "" {
				out[key] = id
			}
		}
		return out
	}
	return mcpRegistry{
		npm:    index(doc.NPM, mcpNPMName),
		pypi:   index(doc.PyPI, mcpPyPIName),
		oci:    index(doc.OCI, mcpOCIName),
		remote: index(doc.Remote, mcpRemoteKey),
	}
}

// mcpIdentity is one server's public identity: the launcher form it was
// declared with and the snapshot spelling of its package, image or endpoint.
type mcpIdentity struct {
	form string // npx, uvx, uv, docker or remote
	id   string
}

// declaration rebuilds the server entry from the launcher form and the
// snapshot constant alone.
func (m mcpIdentity) declaration() map[string]any {
	switch m.form {
	case "remote":
		return map[string]any{"url": m.id}
	case "uv", "docker":
		return map[string]any{"command": m.form, "args": []string{"run", m.id}}
	default:
		return map[string]any{"command": m.form, "args": []string{m.id}}
	}
}

// mcpProjection is the outgoing form of one config body. A declaration's
// command, arguments, URL, headers, environment and name can all carry
// credentials, and no filter can prove an arbitrary string holds none, so
// nothing is copied from it: a server is either matched to a snapshot identity
// or folded into one presence placeholder for its transport.
type mcpProjection struct {
	known         map[mcpIdentity]bool
	local, remote bool
}

// add projects one declaration. An entry with neither a command nor a URL only
// adjusts another server's settings and contributes nothing.
func (p *mcpProjection) add(server map[string]any) {
	if command, args := mcpLaunch(server); command != "" {
		if id, known := mcpKnownLocal(command, args); known {
			p.addKnown(id)
		} else {
			p.local = true
		}
		return
	}
	for _, key := range []string{"url", "serverUrl"} {
		if raw, _ := server[key].(string); raw != "" {
			if id, known := loadMCPRegistry().remote[mcpRemoteKey(raw)]; known {
				p.addKnown(mcpIdentity{form: "remote", id: id})
			} else {
				p.remote = true
			}
			return
		}
	}
}

func (p *mcpProjection) addKnown(id mcpIdentity) {
	if p.known == nil {
		p.known = map[mcpIdentity]bool{}
	}
	p.known[id] = true
}

// addRaw projects one encoded declaration, reporting whether it was an object.
func (p *mcpProjection) addRaw(raw json.RawMessage) bool {
	var server map[string]any
	if json.Unmarshal(raw, &server) != nil || server == nil {
		return false
	}
	p.add(server)
	return true
}

// addAll projects a map of declarations, skipping entries that are not
// objects, and reports whether the map itself decoded.
func (p *mcpProjection) addAll(raw json.RawMessage) bool {
	var servers map[string]json.RawMessage
	if json.Unmarshal(raw, &servers) != nil || servers == nil {
		return false
	}
	for _, server := range servers {
		p.addRaw(server)
	}
	return true
}

// addContainers projects every server map this collector recognizes, including
// Claude Code's per-project mcpServers, and reports whether any held servers.
// The vendor container keys are not kept: the output always uses mcpServers.
// "mcp" is an ordinary enough word to appear as a scalar flag beside the real
// servers, so a value that is not a server map is skipped.
func (p *mcpProjection) addContainers(raw map[string]json.RawMessage) bool {
	found := false
	for _, key := range []string{"mcpServers", "context_servers", "servers", "mcp"} {
		if servers, ok := raw[key]; ok && p.addAll(servers) {
			found = true
		}
	}
	var projects map[string]map[string]json.RawMessage
	if json.Unmarshal(raw["projects"], &projects) == nil {
		for _, project := range projects {
			if p.addAll(project["mcpServers"]) && !p.empty() {
				found = true
			}
		}
	}
	return found
}

func (p *mcpProjection) empty() bool {
	return len(p.known) == 0 && !p.local && !p.remote
}

// servers returns the projected entries keyed by labels generated from their
// identity, with at most one placeholder per transport. No original server
// name is kept.
func (p *mcpProjection) servers() map[string]any {
	out := make(map[string]any, len(p.known)+2)
	for id := range p.known {
		out[id.form+":"+id.id] = id.declaration()
	}
	if p.local {
		out["unidentified-local"] = map[string]any{"command": mcpUnidentifiedLocal}
	}
	if p.remote {
		out["unidentified-remote"] = map[string]any{"url": mcpUnidentifiedRemote}
	}
	return out
}

func (p *mcpProjection) json() ([]byte, bool) {
	out, err := json.Marshal(map[string]any{"mcpServers": p.servers()})
	return out, err == nil
}

// mcpLaunch reads a declaration's command and arguments in each shape the
// collectors accept: a command string with an args list, OpenCode's single
// command array, or Zed's command object. A non-string argument leaves the
// target unknowable, so no arguments are returned and nothing can match.
func mcpLaunch(server map[string]any) (command string, args []string) {
	var rest []any
	switch c := server["command"].(type) {
	case string:
		command = c
		rest, _ = server["args"].([]any)
	case []any:
		if len(c) > 0 {
			command, _ = c[0].(string)
			rest = c[1:]
		}
	case map[string]any:
		command, _ = c["path"].(string)
		rest, _ = c["args"].([]any)
	}
	for _, arg := range rest {
		s, isString := arg.(string)
		if !isString {
			return command, nil
		}
		args = append(args, s)
	}
	return command, args
}

// mcpKnownLocal matches the launcher forms whose target can be read without
// guessing: npx with an optional -y or --yes, uvx, uv run, and docker run with
// the common boolean and environment options before the image. Any other
// option before the target leaves it ambiguous, so it matches nothing.
// Environment operands are skipped and never kept.
func mcpKnownLocal(command string, args []string) (mcpIdentity, bool) {
	reg := loadMCPRegistry()
	switch mcpLauncher(command) {
	case "npx":
		if len(args) > 0 && (args[0] == "-y" || args[0] == "--yes") {
			args = args[1:]
		}
		return mcpLookup("npx", reg.npm, mcpNPMName, args)
	case "uvx":
		return mcpLookup("uvx", reg.pypi, mcpPyPIName, args)
	case "uv":
		if len(args) > 0 && args[0] == "run" {
			return mcpLookup("uv", reg.pypi, mcpPyPIName, args[1:])
		}
	case "docker":
		if len(args) > 0 && args[0] == "run" {
			return mcpLookup("docker", reg.oci, mcpOCIName, dockerImageArgs(args[1:]))
		}
	}
	return mcpIdentity{}, false
}

// mcpLauncher names the launcher a command runs, wherever it is installed and
// without a Windows executable suffix. Only the name is used: the output is
// rebuilt from the launcher's constant, never from the command as written.
func mcpLauncher(command string) string {
	name := strings.ToLower(command[strings.LastIndexAny(command, `/\`)+1:])
	name = strings.TrimSuffix(name, ".exe")
	return strings.TrimSuffix(name, ".cmd")
}

// mcpLookup matches the first argument, which must be the target rather than
// an option, against one snapshot table.
func mcpLookup(form string, table map[string]string, normalize func(string) string, args []string) (mcpIdentity, bool) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return mcpIdentity{}, false
	}
	key := normalize(args[0])
	id, ok := table[key]
	return mcpIdentity{form: form, id: id}, ok && key != ""
}

// dockerImageArgs skips docker run's leading --rm, -i, -t, -it and -e/--env
// options, returning the arguments from the image on.
func dockerImageArgs(args []string) []string {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--rm" || a == "-i" || a == "-t" || a == "-it":
		case a == "-e" || a == "--env":
			i++
		case strings.HasPrefix(a, "--env="):
		default:
			return args[i:]
		}
	}
	return nil
}

// mcpNPMName reduces an npm package operand to its registry name: lowercase,
// scope kept, version or tag removed.
func mcpNPMName(s string) string {
	s = strings.ToLower(s)
	if at := strings.LastIndexByte(s, '@'); at > 0 {
		s = s[:at]
	}
	return s
}

// mcpPyPIName reduces a Python package operand to its normalized registry name:
// version specifiers and extras removed, lowercase, and every run of -, _ and .
// folded to one hyphen.
func mcpPyPIName(s string) string {
	if cut := strings.IndexAny(s, "=<>!~;[@ "); cut >= 0 {
		s = s[:cut]
	}
	var b strings.Builder
	sep := false
	for _, r := range strings.ToLower(s) {
		if r == '-' || r == '_' || r == '.' {
			sep = true
			continue
		}
		if sep && b.Len() > 0 {
			b.WriteByte('-')
		}
		sep = false
		b.WriteRune(r)
	}
	return b.String()
}

// mcpOCIName reduces an image reference to its repository: digest and tag
// removed, lowercase, and Docker Hub's implicit registry and library namespace
// written out.
func mcpOCIName(s string) string {
	s = strings.ToLower(s)
	if at := strings.IndexByte(s, '@'); at >= 0 {
		s = s[:at]
	}
	if colon := strings.LastIndexByte(s, ':'); colon > strings.LastIndexByte(s, '/') {
		s = s[:colon]
	}
	if s == "" {
		return ""
	}
	first, rest, nested := strings.Cut(s, "/")
	switch {
	case !nested:
		return "docker.io/library/" + s
	case first == "index.docker.io":
		return "docker.io/" + rest
	case !strings.ContainsAny(first, ".:") && first != "localhost":
		return "docker.io/" + s
	}
	return s
}

// mcpRemoteKey reduces an endpoint to the form snapshot URLs are matched in:
// userinfo, query and fragment removed, scheme and host lowercased and one
// trailing slash dropped. Anything other than an http or https URL has no key.
func mcpRemoteKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/")
}

// stripJSONCComments removes // and /* */ comments from JSONC content,
// respecting quoted strings (won't strip // inside "https://...").
func stripJSONCComments(input []byte) []byte {
	var out []byte
	i := 0
	for i < len(input) {
		// Skip over strings — don't modify content inside quotes
		if input[i] == '"' {
			out = append(out, input[i])
			i++
			for i < len(input) {
				out = append(out, input[i])
				if input[i] == '\\' && i+1 < len(input) {
					i++
					out = append(out, input[i])
				} else if input[i] == '"' {
					break
				}
				i++
			}
			i++
			continue
		}
		// Block comment
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '*' {
			i += 2
			for i+1 < len(input) && (input[i] != '*' || input[i+1] != '/') {
				i++
			}
			i += 2 // skip */
			continue
		}
		// Line comment
		if i+1 < len(input) && input[i] == '/' && input[i+1] == '/' {
			i += 2
			for i < len(input) && input[i] != '\n' {
				i++
			}
			continue
		}
		out = append(out, input[i])
		i++
	}
	return out
}

// isCopilotProjectMCP limits bare-map parsing to documented project files.
func isCopilotProjectMCP(file string) bool {
	return filepath.Base(file) == ".mcp.json" || filepath.Base(file) == "mcp.json" && filepath.Base(filepath.Dir(file)) == ".github"
}

func filterCopilotMCP(content []byte, allowBare bool) ([]byte, bool) {
	data, err := hujson.Standardize(content)
	var doc map[string]json.RawMessage
	if err != nil || json.Unmarshal(data, &doc) != nil || doc == nil {
		return nil, false
	}
	var servers map[string]json.RawMessage
	if raw, ok := doc["mcpServers"]; ok {
		if json.Unmarshal(raw, &servers) != nil || servers == nil {
			return nil, false
		}
	} else if allowBare {
		servers = doc
	} else {
		return nil, false
	}
	var projected mcpProjection
	for _, raw := range servers {
		if validCopilotMCP(raw) {
			projected.addRaw(raw)
		}
	}
	return projected.json()
}

func validCopilotMCP(raw json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return false
	}
	typ := ""
	if raw, ok := fields["type"]; ok && !decodePortableValue(raw, &typ) {
		return false
	}
	switch typ {
	case "", "local", "stdio":
		if command := jsonString(fields["command"]); command != "" {
			if args, ok := fields["args"]; ok {
				var values []string
				if !decodePortableValue(args, &values) {
					return false
				}
			}
			return true
		}
		return typ == "" && jsonString(fields["url"]) != ""
	case "http", "streamable-http", "sse":
		return jsonString(fields["url"]) != ""
	default:
		return false
	}
}
