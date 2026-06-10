package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// bunSecurityRelevantSections names bunfig.toml sections that warrant a
// highlight in the verbose view. Anything under install.scopes or
// install.registry directly affects where packages come from and how auth
// flows; the rest is mostly developer ergonomics.
var bunSecurityRelevantSections = map[string]bool{
	"install":          true,
	"install.scopes":   true,
	"install.registry": true,
	"install.cache":    true,
	"install.lockfile": true,
}

// PrettyBun renders a BunAudit as a verbose, terminal-friendly report.
//
//nolint:errcheck // terminal output
func PrettyBun(w io.Writer, audit *model.BunAudit, dev model.Device, colorMode string) {
	c := setupColors(colorMode)

	hr := strings.Repeat("─", 76)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "%s%s BUN CONFIG AUDIT %s\n", c.purple, c.bold, c.reset)
	fmt.Fprintf(w, "%s%s%s\n", c.purple, hr, c.reset)
	fmt.Fprintf(w, "  host:   %s%s%s   user: %s%s%s   platform: %s\n",
		c.bold, dev.Hostname, c.reset, c.bold, dev.UserIdentity, c.reset, dev.Platform)
	if audit.Available {
		fmt.Fprintf(w, "  bun:    %s%s%s @ %s\n", c.green, audit.BunVersion, c.reset, audit.BunPath)
	} else {
		fmt.Fprintf(w, "  bun:    %s(not found in PATH — file-only audit)%s\n", c.dim, c.reset)
	}
	if audit.DiscoveryError != "" {
		fmt.Fprintf(w, "  %swarn: %s%s\n", c.dim, audit.DiscoveryError, c.reset)
	}
	// bun has no `config list` equivalent — call that out so the absence
	// isn't mistaken for a bug.
	fmt.Fprintf(w, "  %s(bun has no `config list` — effective view rendered as the union of parsed files)%s\n",
		c.dim, c.reset)
	fmt.Fprintln(w)

	// --- discovered bunfig.toml files ---
	fmt.Fprintf(w, "%s%s┌── DISCOVERED bunfig.toml FILES (%d) %s\n",
		c.purple, c.bold, len(audit.Files), c.reset)
	if len(audit.Files) == 0 {
		fmt.Fprintf(w, "  %sno bunfig.toml at any scope%s\n", c.dim, c.reset)
	}
	files := append([]model.BunConfigFile(nil), audit.Files...)
	sort.SliceStable(files, func(i, j int) bool {
		if bunScopeRank(files[i].Scope) != bunScopeRank(files[j].Scope) {
			return bunScopeRank(files[i].Scope) < bunScopeRank(files[j].Scope)
		}
		return files[i].Path < files[j].Path
	})
	for _, f := range files {
		printBunFileVerbose(w, c, f)
	}
	fmt.Fprintln(w)

	// --- side-channel .npmrc files ---
	if len(audit.NPMRCFiles) > 0 {
		fmt.Fprintf(w, "%s%s┌── .npmrc FILES bun WOULD READ FOR AUTH (%d) %s\n",
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
	printBunEnvVerbose(w, c, audit.Env)
}

func bunScopeRank(s string) int {
	switch s {
	case "user":
		return 0
	case "user-xdg":
		return 1
	case "project":
		return 2
	}
	return 99
}

//nolint:errcheck // terminal output
func printBunFileVerbose(w io.Writer, c *colors, f model.BunConfigFile) {
	scopeTag := strings.ToUpper(f.Scope)
	fmt.Fprintf(w, "│\n│ %s%s[%s]%s %s\n", c.purple, c.bold, scopeTag, c.reset, f.Path)

	if !f.Exists {
		fmt.Fprintf(w, "│   %s(file does not exist — bun would skip this scope)%s\n", c.dim, c.reset)
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
		// continue — parser is tolerant; sections may be partially populated
	}

	if len(f.Sections) == 0 {
		fmt.Fprintf(w, "│   %s(no sections parsed)%s\n", c.dim, c.reset)
		return
	}

	for _, sec := range f.Sections {
		secLabel := sec.Name
		if secLabel == "" {
			secLabel = "(top-level)"
		}
		secMark := "  "
		if bunSecurityRelevantSections[sec.Name] || strings.HasPrefix(sec.Name, "install.scopes") {
			secMark = c.purple + "★ " + c.reset
		}
		fmt.Fprintf(w, "│   %s%s[%s]%s\n", secMark, c.bold, secLabel, c.reset)
		for _, e := range sec.Entries {
			badges := []string{}
			switch {
			case e.IsAuth && e.IsEnvRef:
				badges = append(badges, c.green+"AUTH:env-ref"+c.reset)
			case e.IsAuth:
				badges = append(badges, c.bold+"AUTH:hardcoded"+c.reset)
			case e.IsEnvRef:
				badges = append(badges, "env-ref")
			}
			badgeStr := ""
			if len(badges) > 0 {
				badgeStr = " " + strings.Join(badges, " ")
			}
			fmt.Fprintf(w, "│       %-42s = %s%s%s%s\n",
				e.Key, c.dim, e.DisplayValue, c.reset, badgeStr)
		}
	}
}

//nolint:errcheck // terminal output
func printBunEnvVerbose(w io.Writer, c *colors, env []model.NPMRCEnvVar) {
	fmt.Fprintf(w, "%s%s┌── bun-RELEVANT ENVIRONMENT VARIABLES %s\n",
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
