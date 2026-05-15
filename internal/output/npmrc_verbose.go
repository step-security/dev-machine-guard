package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// securityRelevantKeys are the npm config keys that materially change install
// behavior or trust posture. We highlight them in the verbose view so they
// stand out from the 100+ other keys npm exposes.
var securityRelevantKeys = map[string]string{
	"registry":              "where unscoped packages come from",
	"strict-ssl":            "TLS verification on registry traffic",
	"ignore-scripts":        "block lifecycle scripts (preinstall/install/postinstall)",
	"script-shell":          "shell used by lifecycle scripts and `npm run`",
	"node-options":          "NODE_OPTIONS for spawned scripts (--require= is dangerous)",
	"min-release-age":       "skip versions newer than N days (defense vs just-published worms)",
	"audit":                 "run npm audit on install",
	"audit-level":           "severity threshold for audit failures",
	"package-lock":          "honor lockfile for reproducible installs",
	"replace-registry-host": "rewrite registry host in lockfile entries at install",
	"ca":                    "inline-trusted CA cert(s)",
	"cafile":                "path to CA cert bundle",
	"proxy":                 "outbound proxy",
	"https-proxy":           "outbound HTTPS proxy",
	"prefix":                "global install location",
	"cache":                 "fetched-tarball cache directory",
	"globalconfig":          "path to global .npmrc",
	"userconfig":            "path to user .npmrc",
}

// PrettyNPMRC renders an NPMRCAudit as a verbose, terminal-friendly report.
// It's the implementation behind `--npmrc`: focused, deeper than the default
// summary, but still scannable.
//
//nolint:errcheck // terminal output
func PrettyNPMRC(w io.Writer, audit *model.NPMRCAudit, dev model.Device, colorMode string) {
	c := setupColors(colorMode)

	hr := strings.Repeat("─", 76)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "%s%s NPM CONFIG AUDIT %s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "  host:   %s%s%s   user: %s%s%s   platform: %s\n",
		c.bold, dev.Hostname, c.reset, c.bold, dev.UserIdentity, c.reset, dev.Platform)
	if audit.Available {
		fmt.Fprintf(w, "  npm:    %s%s%s @ %s\n", c.green, audit.NPMVersion, c.reset, audit.NPMPath)
	} else {
		fmt.Fprintf(w, "  npm:    %s(not found in PATH — file-only audit)%s\n", c.dim, c.reset)
	}
	if audit.DiscoveryError != "" {
		fmt.Fprintf(w, "  %swarn: %s%s\n", c.dim, audit.DiscoveryError, c.reset)
	}
	fmt.Fprintln(w)

	// --- discovered files ---
	fmt.Fprintf(w, "%s%s┌── DISCOVERED .npmrc FILES (%d) %s\n",
		c.purple, c.bold, len(audit.Files), c.reset)
	if len(audit.Files) == 0 {
		fmt.Fprintf(w, "  %sno .npmrc files at any scope%s\n", c.dim, c.reset)
	}
	// Stable display order: builtin → global → user → project (then by path).
	files := append([]model.NPMRCFile(nil), audit.Files...)
	sort.SliceStable(files, func(i, j int) bool {
		if scopeRank(files[i].Scope) != scopeRank(files[j].Scope) {
			return scopeRank(files[i].Scope) < scopeRank(files[j].Scope)
		}
		return files[i].Path < files[j].Path
	})
	for _, f := range files {
		printNPMRCFileVerbose(w, c, f)
	}
	fmt.Fprintln(w)

	// --- effective config ---
	if audit.Effective != nil {
		printEffectiveVerbose(w, c, audit.Effective)
	}

	// --- env vars ---
	printEnvVerbose(w, c, audit.Env)
}

func scopeRank(s string) int {
	switch s {
	case "builtin":
		return 0
	case "global":
		return 1
	case "user":
		return 2
	case "project":
		return 3
	}
	return 99
}

//nolint:errcheck // terminal output
func printNPMRCFileVerbose(w io.Writer, c *colors, f model.NPMRCFile) {
	scopeTag := strings.ToUpper(f.Scope)
	fmt.Fprintf(w, "│\n│ %s%s[%s]%s %s\n", c.purple, c.bold, scopeTag, c.reset, f.Path)

	if !f.Exists {
		fmt.Fprintf(w, "│   %s(file does not exist — npm would skip this scope)%s\n", c.dim, c.reset)
		return
	}

	// Metadata line.
	mtime := ""
	if f.ModTimeUnix > 0 {
		mtime = time.Unix(f.ModTimeUnix, 0).Format("2006-01-02 15:04:05")
	}
	owner := "?"
	if f.OwnerName != "" {
		owner = fmt.Sprintf("%s:%s", f.OwnerName, f.GroupName)
	}
	sha := f.SHA256
	if len(sha) > 12 {
		sha = sha[:12]
	}
	fmt.Fprintf(w, "│   %smode=%s size=%db owner=%s mtime=%s sha=%s%s\n",
		c.dim, f.Mode, f.SizeBytes, owner, mtime, sha, c.reset)

	// Notable flags.
	flags := []string{}
	if f.SymlinkTo != "" {
		flags = append(flags, fmt.Sprintf("symlink → %s", f.SymlinkTo))
	}
	if f.GitTracked {
		flags = append(flags, c.bold+"GIT-TRACKED"+c.reset+" (committed — credentials would be exposed wherever the repo is)")
	} else if f.InGitRepo {
		flags = append(flags, "inside a git repo (untracked)")
	}
	if len(flags) > 0 {
		for _, fl := range flags {
			fmt.Fprintf(w, "│   %s· %s%s\n", c.dim, fl, c.reset)
		}
	}

	if f.ParseError != "" {
		fmt.Fprintf(w, "│   %sparse error: %s%s\n", c.dim, f.ParseError, c.reset)
		return
	}

	if len(f.Entries) == 0 {
		fmt.Fprintf(w, "│   %s(empty file)%s\n", c.dim, c.reset)
		return
	}

	// Entries — each one with line number, classification badge, key, redacted value.
	fmt.Fprintf(w, "│   %sentries (%d):%s\n", c.dim, len(f.Entries), c.reset)
	for _, e := range f.Entries {
		key := e.Key
		if e.IsArray {
			key += "[]"
		}

		// Classification badges
		badges := []string{}
		switch {
		case e.IsAuth && e.IsEnvRef:
			badges = append(badges, c.green+"AUTH:env-ref"+c.reset)
		case e.IsAuth:
			badges = append(badges, c.bold+"AUTH:hardcoded"+c.reset)
		case e.IsEnvRef:
			badges = append(badges, "env-ref")
		}
		if _, ok := securityRelevantKeys[e.Key]; ok {
			badges = append(badges, c.purple+"sec-relevant"+c.reset)
		}
		badgeStr := ""
		if len(badges) > 0 {
			badgeStr = " " + strings.Join(badges, " ")
		}

		fmt.Fprintf(w, "│   %s%4d:%s  %-42s = %s%s%s%s\n",
			c.dim, e.LineNum, c.reset, key, c.dim, e.DisplayValue, c.reset, badgeStr)
		if e.IsAuth && e.IsEnvRef && len(e.EnvRefVars) > 0 {
			fmt.Fprintf(w, "│         %s         resolves from env: %s%s\n",
				c.dim, strings.Join(e.EnvRefVars, ", "), c.reset)
		}
	}

	// Drift detection (per-file modification, "previous scan was N ago", etc.)
	// and per-project effective overrides ("running npm in this dir flips X")
	// are intentionally out of scope for this iteration. See
	// .plans/0005-npmrc-audit.md for the documented extension points.
}

//nolint:errcheck // terminal output
func printEffectiveVerbose(w io.Writer, c *colors, eff *model.NPMRCEffective) {
	fmt.Fprintf(w, "%s%s┌── EFFECTIVE CONFIG (what npm would actually use) %s\n",
		c.purple, c.bold, c.reset)

	if eff.Error != "" {
		fmt.Fprintf(w, "│   %swarn: %s%s\n│\n", c.dim, eff.Error, c.reset)
	}

	// Group keys by source so the layered structure is visible at a glance.
	bySource := map[string][]string{}
	for k := range eff.Config {
		src := eff.SourceByKey[k]
		if src == "" {
			src = "default"
		}
		bySource[src] = append(bySource[src], k)
	}
	for _, ks := range bySource {
		sort.Strings(ks)
	}

	// Display order: paths/explicit-layer sources first (those are what the
	// user changed); "default" last (compiled-in baseline, usually noise).
	sources := make([]string, 0, len(bySource))
	for s := range bySource {
		sources = append(sources, s)
	}
	sort.SliceStable(sources, func(i, j int) bool {
		// "default" always sorts last.
		if sources[i] == "default" {
			return false
		}
		if sources[j] == "default" {
			return true
		}
		return sources[i] < sources[j]
	})

	for _, src := range sources {
		keys := bySource[src]
		isDefault := src == "default"

		// In default-section, only show keys that are security-relevant —
		// printing 100+ default values is noise.
		shown := keys
		hidden := 0
		if isDefault {
			filtered := keys[:0]
			for _, k := range keys {
				if _, ok := securityRelevantKeys[k]; ok {
					filtered = append(filtered, k)
				}
			}
			hidden = len(keys) - len(filtered)
			shown = filtered
		}

		fmt.Fprintf(w, "│\n│ %sfrom %s%s%s  (%d keys)\n",
			c.dim, c.bold, src, c.reset, len(keys))

		for _, k := range shown {
			v := formatEffValue(eff.Config[k])
			marker := "  "
			if _, ok := securityRelevantKeys[k]; ok {
				marker = c.purple + "★ " + c.reset
			}
			fmt.Fprintf(w, "│   %s%-42s = %s%s%s\n", marker, k, c.dim, v, c.reset)
		}
		if isDefault && hidden > 0 {
			fmt.Fprintf(w, "│   %s(+%d default values not shown)%s\n", c.dim, hidden, c.reset)
		}
	}
	fmt.Fprintln(w)
}

// formatEffValue stringifies an arbitrary JSON value from npm config.
// Strings render bare; everything else uses fmt's default %v.
func formatEffValue(v any) string {
	if v == nil {
		return "null"
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

//nolint:errcheck // terminal output
func printEnvVerbose(w io.Writer, c *colors, env []model.NPMRCEnvVar) {
	fmt.Fprintf(w, "%s%s┌── npm-RELEVANT ENVIRONMENT VARIABLES %s\n",
		c.purple, c.bold, c.reset)
	setCount := 0
	for _, e := range env {
		if e.Set {
			setCount++
		}
	}
	fmt.Fprintf(w, "│   %s%d set, %d unset (unset names are recorded so Phase B can detect transitions)%s\n",
		c.dim, setCount, len(env)-setCount, c.reset)
	fmt.Fprintln(w, "│")
	for _, e := range env {
		state := c.dim + "unset" + c.reset
		val := ""
		if e.Set {
			state = c.green + " set " + c.reset
			val = " = " + c.dim + e.DisplayValue + c.reset
		}
		fmt.Fprintf(w, "│   [%s] %s%s\n", state, e.Name, val)
	}
	fmt.Fprintln(w)
}
