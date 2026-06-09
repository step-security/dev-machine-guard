package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// pnpmSecurityRelevantKeys are the pnpm-specific config keys (on top of npm's
// shared set) that materially change install behavior or trust posture. Used
// to flag entries in the verbose view.
var pnpmSecurityRelevantKeys = map[string]string{
	"auto-install-peers":              "auto-install missing peer deps (silently widens the dep tree)",
	"strict-peer-dependencies":        "fail install on unmet peer deps",
	"node-linker":                     "store layout: isolated | hoisted | pnp",
	"package-import-method":           "how pkgs are linked from the store",
	"min-release-age":                 "skip versions newer than N days (defense vs just-published worms)",
	"min-release-age-exclude":         "package names exempt from min-release-age",
	"verify-store-integrity":          "verify store contents on each install",
	"side-effects-cache":              "cache build artifacts of native deps",
	"shamefully-hoist":                "flatten node_modules (compatibility shim; loosens isolation)",
	"public-hoist-pattern":            "patterns hoisted to the top of node_modules",
	"hoist-pattern":                   "patterns hoisted to virtual store root",
	"dedupe-peer-dependents":          "share peer-dependent installations",
	"prefer-frozen-lockfile":          "fail install if lockfile doesn't match package.json",
	"use-node-version":                "pinned node version for this project",
	"manage-package-manager-versions": "enforce package-manager pin from package.json",
}

// PrettyPnpm renders a PnpmAudit as a verbose, terminal-friendly report.
// The structure mirrors PrettyNPMRC; entries are sorted by scope precedence
// (global → user → project) then path.
//
//nolint:errcheck // terminal output
func PrettyPnpm(w io.Writer, audit *model.PnpmAudit, dev model.Device, colorMode string) {
	c := setupColors(colorMode)

	hr := strings.Repeat("─", 76)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "%s%s PNPM CONFIG AUDIT %s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "  host:   %s%s%s   user: %s%s%s   platform: %s\n",
		c.bold, dev.Hostname, c.reset, c.bold, dev.UserIdentity, c.reset, dev.Platform)
	if audit.Available {
		fmt.Fprintf(w, "  pnpm:   %s%s%s @ %s\n", c.green, audit.PnpmVersion, c.reset, audit.PnpmPath)
	} else {
		fmt.Fprintf(w, "  pnpm:   %s(not found in PATH — file-only audit)%s\n", c.dim, c.reset)
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
	files := append([]model.NPMRCFile(nil), audit.Files...)
	sort.SliceStable(files, func(i, j int) bool {
		if scopeRank(files[i].Scope) != scopeRank(files[j].Scope) {
			return scopeRank(files[i].Scope) < scopeRank(files[j].Scope)
		}
		return files[i].Path < files[j].Path
	})
	for _, f := range files {
		printPnpmFileVerbose(w, c, f)
	}
	fmt.Fprintln(w)

	// --- effective config ---
	if audit.Effective != nil {
		printPnpmEffectiveVerbose(w, c, audit.Effective)
	}

	// --- env vars ---
	printPnpmEnvVerbose(w, c, audit.Env)
}

//nolint:errcheck // terminal output
func printPnpmFileVerbose(w io.Writer, c *colors, f model.NPMRCFile) {
	scopeTag := strings.ToUpper(f.Scope)
	fmt.Fprintf(w, "│\n│ %s%s[%s]%s %s\n", c.purple, c.bold, scopeTag, c.reset, f.Path)

	if !f.Exists {
		fmt.Fprintf(w, "│   %s(file does not exist — pnpm would skip this scope)%s\n", c.dim, c.reset)
		return
	}

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

	flags := []string{}
	if f.SymlinkTo != "" {
		flags = append(flags, fmt.Sprintf("symlink → %s", f.SymlinkTo))
	}
	if f.GitTracked {
		flags = append(flags, c.bold+"GIT-TRACKED"+c.reset+" (committed — credentials would be exposed wherever the repo is)")
	} else if f.InGitRepo {
		flags = append(flags, "inside a git repo (untracked)")
	}
	for _, fl := range flags {
		fmt.Fprintf(w, "│   %s· %s%s\n", c.dim, fl, c.reset)
	}

	if f.ParseError != "" {
		fmt.Fprintf(w, "│   %sparse error: %s%s\n", c.dim, f.ParseError, c.reset)
		return
	}

	if len(f.Entries) == 0 {
		fmt.Fprintf(w, "│   %s(empty file)%s\n", c.dim, c.reset)
		return
	}

	fmt.Fprintf(w, "│   %sentries (%d):%s\n", c.dim, len(f.Entries), c.reset)
	for _, e := range f.Entries {
		key := e.Key
		if e.IsArray {
			key += "[]"
		}

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
		} else if _, ok := pnpmSecurityRelevantKeys[e.Key]; ok {
			badges = append(badges, c.purple+"pnpm-sec"+c.reset)
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
}

//nolint:errcheck // terminal output
func printPnpmEffectiveVerbose(w io.Writer, c *colors, eff *model.PnpmEffective) {
	fmt.Fprintf(w, "%s%s┌── EFFECTIVE CONFIG (pnpm config list --json) %s\n",
		c.purple, c.bold, c.reset)

	if eff.Error != "" {
		fmt.Fprintf(w, "│   %swarn: %s%s\n│\n", c.dim, eff.Error, c.reset)
	}

	if len(eff.Config) == 0 {
		fmt.Fprintf(w, "│   %s(empty — pnpm reported no effective config)%s\n│\n", c.dim, c.reset)
		fmt.Fprintln(w)
		return
	}

	// pnpm doesn't emit source attribution; render alphabetically with
	// security-relevant keys marked.
	keys := make([]string, 0, len(eff.Config))
	for k := range eff.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := formatEffValue(eff.Config[k])
		marker := "  "
		if _, ok := securityRelevantKeys[k]; ok {
			marker = c.purple + "★ " + c.reset
		} else if _, ok := pnpmSecurityRelevantKeys[k]; ok {
			marker = c.purple + "★ " + c.reset
		}
		fmt.Fprintf(w, "│   %s%-42s = %s%s%s\n", marker, k, c.dim, v, c.reset)
	}
	fmt.Fprintln(w)
}

//nolint:errcheck // terminal output
func printPnpmEnvVerbose(w io.Writer, c *colors, env []model.NPMRCEnvVar) {
	fmt.Fprintf(w, "%s%s┌── pnpm-RELEVANT ENVIRONMENT VARIABLES %s\n",
		c.purple, c.bold, c.reset)
	setCount := 0
	for _, e := range env {
		if e.Set {
			setCount++
		}
	}
	fmt.Fprintf(w, "│   %s%d set, %d unset%s\n", c.dim, setCount, len(env)-setCount, c.reset)
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
