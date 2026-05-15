package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// PrettyPipConfig renders a pip-only audit in a verbose, terminal-friendly
// format. Behind the `--pipconfig` flag.
//
//nolint:errcheck // terminal output
func PrettyPipConfig(w io.Writer, audit *model.PipAudit, dev model.Device, colorMode string) {
	c := setupColors(colorMode)

	hr := strings.Repeat("─", 76)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "%s%s PIP CONFIG AUDIT %s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "  host:   %s%s%s   user: %s%s%s   platform: %s\n",
		c.bold, dev.Hostname, c.reset, c.bold, dev.UserIdentity, c.reset, dev.Platform)
	if audit.Available {
		fmt.Fprintf(w, "  pip:    %s%s%s @ %s   (%s)\n", c.green, audit.Version, c.reset, audit.Path, audit.Invocation)
	} else {
		fmt.Fprintf(w, "  pip:    %s(not found in PATH — file-only audit)%s\n", c.dim, c.reset)
	}
	if audit.DiscoveryError != "" {
		fmt.Fprintf(w, "  %swarn: %s%s\n", c.dim, audit.DiscoveryError, c.reset)
	}
	fmt.Fprintln(w)

	// --- findings (most important; show first) ---
	printPipFindings(w, c, audit.Findings)

	// --- discovered files ---
	printPipFiles(w, c, audit.Files)

	// --- effective merged view ---
	if audit.Effective != nil {
		printPipEffective(w, c, audit.Effective)
	}

	// --- env vars (only shows ones that are set) ---
	printPipEnvVars(w, c, audit.EnvVars)

	// --- netrc status ---
	printPipNetrc(w, c, audit.Netrc)
}

//nolint:errcheck // terminal output
func printPipFindings(w io.Writer, c *colors, findings []model.PipFinding) {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "%s%s┌── FINDINGS%s   %sCRITICAL %d  HIGH %d  MEDIUM %d  LOW %d  INFO %d%s\n",
		c.purple, c.bold, c.reset,
		c.dim, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"], c.reset)
	if len(findings) == 0 {
		fmt.Fprintf(w, "│   %sno findings — pip configuration looks clean%s\n", c.dim, c.reset)
		fmt.Fprintln(w)
		return
	}
	for _, f := range findings {
		printPipFinding(w, c, f)
	}
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printPipFinding(w io.Writer, c *colors, f model.PipFinding) {
	sevColor := c.dim
	switch f.Severity {
	case "CRITICAL":
		sevColor = c.bold + c.purple
	case "HIGH":
		sevColor = c.bold
	case "MEDIUM":
		sevColor = c.purple
	case "LOW":
		sevColor = c.dim
	case "INFO":
		sevColor = c.green
	}
	source := f.Source
	if f.Section != "" {
		source = fmt.Sprintf("%s [%s]", source, f.Section)
	}
	fmt.Fprintf(w, "│  %s%-8s%s  %s%s%s  %s%s%s\n",
		sevColor, f.Severity, c.reset, c.bold, f.ID, c.reset, c.dim, f.Category, c.reset)
	fmt.Fprintf(w, "│      %ssource:%s   %s\n", c.dim, c.reset, source)
	if f.Key != "" {
		fmt.Fprintf(w, "│      %skey:%s      %s\n", c.dim, c.reset, f.Key)
	}
	if f.ValueShown != "" {
		fmt.Fprintf(w, "│      %svalue:%s    %s\n", c.dim, c.reset, f.ValueShown)
	}
	if f.Detail != "" {
		fmt.Fprintf(w, "│      %sdetail:%s   %s\n", c.dim, c.reset, f.Detail)
	}
	if f.Remediation != "" {
		fmt.Fprintf(w, "│      %sfix:%s      %s\n", c.dim, c.reset, f.Remediation)
	}
	fmt.Fprintln(w, "│")
}

//nolint:errcheck // terminal output
func printPipFiles(w io.Writer, c *colors, files []model.PipConfigFile) {
	fmt.Fprintf(w, "%s%s┌── DISCOVERED CONFIG FILES (%d)%s\n", c.purple, c.bold, len(files), c.reset)
	if len(files) == 0 {
		fmt.Fprintf(w, "│   %sno pip config files at any scope%s\n", c.dim, c.reset)
		fmt.Fprintln(w)
		return
	}
	// Stable order: layer rank → path.
	sorted := append([]model.PipConfigFile(nil), files...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if pipLayerRank(sorted[i].Layer) != pipLayerRank(sorted[j].Layer) {
			return pipLayerRank(sorted[i].Layer) < pipLayerRank(sorted[j].Layer)
		}
		return sorted[i].Path < sorted[j].Path
	})
	for _, f := range sorted {
		printPipFile(w, c, f)
	}
	fmt.Fprintln(w)
}

func pipLayerRank(l string) int {
	switch l {
	case "global":
		return 0
	case "user-legacy":
		return 1
	case "user":
		return 2
	case "site":
		return 3
	case "PIP_CONFIG_FILE":
		return 4
	}
	return 99
}

//nolint:errcheck // terminal output
func printPipFile(w io.Writer, c *colors, f model.PipConfigFile) {
	tag := strings.ToUpper(f.Layer)
	fmt.Fprintf(w, "│\n│ %s%s[%s]%s %s\n", c.purple, c.bold, tag, c.reset, f.Path)
	if !f.Exists {
		fmt.Fprintf(w, "│   %s(file does not exist — pip would skip this scope)%s\n", c.dim, c.reset)
		return
	}
	owner := "?"
	if f.OwnerName != "" {
		owner = fmt.Sprintf("%s:%s", f.OwnerName, f.GroupName)
	}
	sha := f.SHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	fmt.Fprintf(w, "│   %smode=%s size=%db owner=%s sha=%s%s\n",
		c.dim, f.Mode, f.SizeBytes, owner, sha, c.reset)
	if f.GitTracked {
		fmt.Fprintf(w, "│   %s· %sGIT-TRACKED%s%s — committed credentials/config would be exposed wherever the repo is\n", c.dim, c.bold, c.reset, c.dim)
	} else if f.InGitRepo {
		fmt.Fprintf(w, "│   %s· inside a git repo (untracked)%s\n", c.dim, c.reset)
	}
	if f.ParseError != "" {
		fmt.Fprintf(w, "│   %sparse error: %s%s\n", c.dim, f.ParseError, c.reset)
		return
	}
	if len(f.Sections) == 0 {
		fmt.Fprintf(w, "│   %s(empty file)%s\n", c.dim, c.reset)
		return
	}
	for _, sec := range f.Sections {
		fmt.Fprintf(w, "│   %s[%s]%s\n", c.bold, sec.Name, c.reset)
		for _, kv := range sec.Entries {
			vals := kv.Display
			if vals == "" && len(kv.Values) > 0 {
				vals = strings.Join(kv.Values, ", ")
			}
			fmt.Fprintf(w, "│     %s%4d:%s  %-32s = %s%s%s\n",
				c.dim, kv.LineNum, c.reset, kv.Key, c.dim, vals, c.reset)
		}
	}
}

//nolint:errcheck // terminal output
func printPipEffective(w io.Writer, c *colors, eff *model.PipEffective) {
	fmt.Fprintf(w, "%s%s┌── EFFECTIVE CONFIG (what pip would actually use) %s\n", c.purple, c.bold, c.reset)
	if eff.Error != "" {
		fmt.Fprintf(w, "│   %swarn: %s%s\n", c.dim, eff.Error, c.reset)
	}
	if len(eff.Config) == 0 {
		fmt.Fprintf(w, "│   %s(no merged config returned — pip not available, or no config set)%s\n", c.dim, c.reset)
		fmt.Fprintln(w)
		return
	}
	keys := make([]string, 0, len(eff.Config))
	for k := range eff.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		src := eff.SourceByKey[k]
		if src == "" {
			src = "(source not reported by pip)"
		}
		fmt.Fprintf(w, "│   %-40s = %s%s%s   %sfrom %s%s\n",
			k, c.dim, eff.Config[k], c.reset, c.dim, src, c.reset)
	}
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printPipEnvVars(w io.Writer, c *colors, env []model.PipEnvVar) {
	if len(env) == 0 {
		return
	}
	fmt.Fprintf(w, "%s%s┌── PIP-RELEVANT ENVIRONMENT VARIABLES (set: %d)%s\n", c.purple, c.bold, len(env), c.reset)
	for _, e := range env {
		fmt.Fprintf(w, "│   %s = %s%s%s\n", e.Name, c.dim, e.Display, c.reset)
	}
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printPipNetrc(w io.Writer, c *colors, n *model.PipNetrcStatus) {
	if n == nil {
		return
	}
	fmt.Fprintf(w, "%s%s┌── ~/.netrc%s\n", c.purple, c.bold, c.reset)
	if !n.Exists {
		fmt.Fprintf(w, "│   %snot present%s\n", c.dim, c.reset)
	} else {
		fmt.Fprintf(w, "│   %spath:%s %s   %smode:%s %s\n", c.dim, c.reset, n.Path, c.dim, c.reset, n.Mode)
		fmt.Fprintf(w, "│   %s(content not parsed — .netrc is shared with curl/wget/twine; that's a separate audit)%s\n", c.dim, c.reset)
	}
	fmt.Fprintln(w)
}
