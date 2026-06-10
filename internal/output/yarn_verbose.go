package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// yarnSecurityRelevantKeys are config keys (covering both classic and the
// flattened berry form) that materially affect install behavior or trust
// posture. Used to flag entries in the verbose view.
var yarnSecurityRelevantKeys = map[string]bool{
	// classic
	"registry":            true,
	"strict-ssl":          true,
	"ignore-scripts":      true,
	"network-timeout":     true,
	"yarn-offline-mirror": true,
	"cafile":              true,
	"ca":                  true,
	"proxy":               true,
	"https-proxy":         true,
	// berry
	"npmRegistryServer":       true,
	"npmPublishRegistry":      true,
	"npmAlwaysAuth":           true,
	"enableStrictSsl":         true,
	"enableScripts":           true,
	"enableImmutableInstalls": true,
	"enableNetwork":           true,
	"unsafeHttpWhitelist":     true,
	"httpProxy":               true,
	"httpsProxy":              true,
	"caFilePath":              true,
	"httpsCaFilePath":         true,
}

// PrettyYarn renders a YarnAudit as a verbose, terminal-friendly report.
// Surfaces classic + berry flavors side by side and calls out v1-binary-with-
// berry-file (or vice versa) mismatches.
//
//nolint:errcheck // terminal output
func PrettyYarn(w io.Writer, audit *model.YarnAudit, dev model.Device, colorMode string) {
	c := setupColors(colorMode)

	hr := strings.Repeat("─", 76)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "%s%s YARN CONFIG AUDIT %s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "  host:   %s%s%s   user: %s%s%s   platform: %s\n",
		c.bold, dev.Hostname, c.reset, c.bold, dev.UserIdentity, c.reset, dev.Platform)
	if audit.Available {
		flavor := audit.Flavor
		if flavor == "" {
			flavor = "unknown"
		}
		fmt.Fprintf(w, "  yarn:   %s%s%s (%s) @ %s\n", c.green, audit.YarnVersion, c.reset, flavor, audit.YarnPath)
	} else {
		fmt.Fprintf(w, "  yarn:   %s(not found in PATH — file-only audit)%s\n", c.dim, c.reset)
	}
	if audit.DiscoveryError != "" {
		fmt.Fprintf(w, "  %swarn: %s%s\n", c.dim, audit.DiscoveryError, c.reset)
	}

	// Flavor-mismatch hint: a v1 binary that reads berry files (or vice
	// versa) is itself a useful signal worth surfacing in the verbose view.
	if audit.Available {
		mismatch := false
		for _, f := range audit.Files {
			if !f.Exists {
				continue
			}
			if (audit.Flavor == "classic" && f.Flavor == "berry") ||
				(audit.Flavor == "berry" && f.Flavor == "classic") {
				mismatch = true
				break
			}
		}
		if mismatch {
			fmt.Fprintf(w, "  %s★ flavor mismatch: a file in a different yarn flavor was discovered alongside the %s binary%s\n",
				c.purple, audit.Flavor, c.reset)
		}
	}
	fmt.Fprintln(w)

	// --- discovered files ---
	fmt.Fprintf(w, "%s%s┌── DISCOVERED yarn CONFIG FILES (%d) %s\n",
		c.purple, c.bold, len(audit.Files), c.reset)
	if len(audit.Files) == 0 {
		fmt.Fprintf(w, "  %sno yarn config files at any scope%s\n", c.dim, c.reset)
	}
	files := append([]model.YarnConfigFile(nil), audit.Files...)
	sort.SliceStable(files, func(i, j int) bool {
		if yarnScopeRank(files[i].Scope) != yarnScopeRank(files[j].Scope) {
			return yarnScopeRank(files[i].Scope) < yarnScopeRank(files[j].Scope)
		}
		if files[i].Flavor != files[j].Flavor {
			return files[i].Flavor < files[j].Flavor
		}
		return files[i].Path < files[j].Path
	})
	for _, f := range files {
		printYarnFileVerbose(w, c, f)
	}
	fmt.Fprintln(w)

	// --- side-channel .npmrc files ---
	if len(audit.NPMRCFiles) > 0 {
		fmt.Fprintf(w, "%s%s┌── .npmrc FILES yarn WOULD READ FOR AUTH (%d) %s\n",
			c.purple, c.bold, len(audit.NPMRCFiles), c.reset)
		nf := append([]model.NPMRCFile(nil), audit.NPMRCFiles...)
		sort.SliceStable(nf, func(i, j int) bool {
			if scopeRank(nf[i].Scope) != scopeRank(nf[j].Scope) {
				return scopeRank(nf[i].Scope) < scopeRank(nf[j].Scope)
			}
			return nf[i].Path < nf[j].Path
		})
		for _, f := range nf {
			fmt.Fprintf(w, "│ %s[%s]%s %s", c.dim, strings.ToUpper(f.Scope), c.reset, f.Path)
			if !f.Exists {
				fmt.Fprintf(w, "  %s(absent)%s", c.dim, c.reset)
			} else if f.GitTracked {
				fmt.Fprintf(w, "  %sGIT-TRACKED%s", c.bold, c.reset)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	// --- env vars ---
	printYarnEnvVerbose(w, c, audit.Env)
}

func yarnScopeRank(s string) int {
	switch s {
	case "user":
		return 0
	case "project":
		return 1
	}
	return 99
}

//nolint:errcheck // terminal output
func printYarnFileVerbose(w io.Writer, c *colors, f model.YarnConfigFile) {
	scopeTag := strings.ToUpper(f.Scope)
	flavor := strings.ToUpper(f.Flavor)
	fmt.Fprintf(w, "│\n│ %s%s[%s/%s]%s %s\n", c.purple, c.bold, scopeTag, flavor, c.reset, f.Path)

	if !f.Exists {
		fmt.Fprintf(w, "│   %s(file does not exist — yarn would skip this scope)%s\n", c.dim, c.reset)
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
		badges := []string{}
		switch {
		case e.IsAuth && e.IsEnvRef:
			badges = append(badges, c.green+"AUTH:env-ref"+c.reset)
		case e.IsAuth:
			badges = append(badges, c.bold+"AUTH:hardcoded"+c.reset)
		case e.IsEnvRef:
			badges = append(badges, "env-ref")
		}
		if yarnSecurityRelevantKeys[e.Key] {
			badges = append(badges, c.purple+"sec-relevant"+c.reset)
		}
		badgeStr := ""
		if len(badges) > 0 {
			badgeStr = " " + strings.Join(badges, " ")
		}
		line := ""
		if e.LineNum > 0 {
			line = fmt.Sprintf("%4d:", e.LineNum)
		} else {
			line = "    "
		}
		fmt.Fprintf(w, "│   %s%s%s  %-42s = %s%s%s%s\n",
			c.dim, line, c.reset, e.Key, c.dim, e.DisplayValue, c.reset, badgeStr)
		if e.IsAuth && e.IsEnvRef && len(e.EnvRefVars) > 0 {
			fmt.Fprintf(w, "│         %s         resolves from env: %s%s\n",
				c.dim, strings.Join(e.EnvRefVars, ", "), c.reset)
		}
	}
}

//nolint:errcheck // terminal output
func printYarnEnvVerbose(w io.Writer, c *colors, env []model.NPMRCEnvVar) {
	fmt.Fprintf(w, "%s%s┌── yarn-RELEVANT ENVIRONMENT VARIABLES %s\n",
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
