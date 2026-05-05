package detector

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// suspectCommExact is the allowlist of process command-name basenames worth
// reporting as candidates for "who modified this .npmrc." Match is exact
// against the COMM column from `ps` (the binary basename without args), so
// "gnome-shell" doesn't match "sh" the way a substring filter would.
//
// Editors and tools that frequently launch with absolute or hyphenated
// paths still match because we strip to basename before comparing.
var suspectCommExact = map[string]struct{}{
	"npm":     {},
	"npx":     {},
	"yarn":    {},
	"pnpm":    {},
	"bun":     {},
	"node":    {},
	"nodejs":  {},
	"sh":      {},
	"bash":    {},
	"zsh":     {},
	"dash":    {},
	"fish":    {},
	"vi":      {},
	"vim":     {},
	"nvim":    {},
	"nano":    {},
	"emacs":   {},
	"git":     {},
	"curl":    {},
	"wget":    {},
	"python":  {},
	"python3": {},
	"perl":    {},
	"ruby":    {},
	// Editors that show up under their full binary name on most distros.
	"code":     {},
	"cursor":   {},
	"windsurf": {},
}

// suspectArgsContains catches processes whose comm doesn't match exactly
// but whose argv string indicates an npmrc-relevant action. We keep this
// list short and specific so it stays low-noise. Substrings are matched
// against the full args string, lowercased.
var suspectArgsContains = []string{
	"npm install", "npm publish", "npm config",
	"yarn install", "yarn add",
	"pnpm install", "pnpm add",
	".npmrc",
}

// EnrichAttribution adds human-readable notes and (when the file changed
// recently) a process-list snapshot to each NPMRCFileModification on the
// diff. The diff struct is mutated in place. Safe to call with a nil diff
// or a diff that has no modifications.
//
// Attribution is best-effort. We never claim "process X did it"; we say
// "here are the candidate processes that were running when we observed
// the change." Forensic-grade attribution requires audit logs that we
// don't have access to from a normal-priv agent.
func EnrichAttribution(ctx context.Context, exec executor.Executor, diff *model.NPMRCDiff, scanTimeUnix int64) {
	if diff == nil || len(diff.ModifiedFiles) == 0 {
		return
	}

	// Lazy-load the process list: only run `ps` once even if multiple
	// modified files all qualify for the recent-mtime path.
	var procListCached []model.NPMRCSuspect
	procListLoaded := false

	loadProcs := func() []model.NPMRCSuspect {
		if procListLoaded {
			return procListCached
		}
		procListCached = captureSuspects(ctx, exec)
		procListLoaded = true
		return procListCached
	}

	for i := range diff.ModifiedFiles {
		mod := &diff.ModifiedFiles[i]

		// Owner change is the strongest "different writer" signal.
		if mod.OwnerChanged != nil {
			mod.AttributionNotes = append(mod.AttributionNotes,
				fmt.Sprintf("file owner changed from %q to %q — write performed by a different user account",
					mod.OwnerChanged.From, mod.OwnerChanged.To))
		}
		if mod.GroupChanged != nil {
			mod.AttributionNotes = append(mod.AttributionNotes,
				fmt.Sprintf("file group changed from %q to %q",
					mod.GroupChanged.From, mod.GroupChanged.To))
		}
		if mod.ModeChanged != nil {
			note := fmt.Sprintf("file mode changed from %s to %s", mod.ModeChanged.From, mod.ModeChanged.To)
			// Loosened-mode flag: if the new mode is more permissive than
			// the old one (e.g. 0600 → 0644), call it out.
			if isModeRelaxed(mod.ModeChanged.From, mod.ModeChanged.To) {
				note += " — permissions relaxed"
			}
			mod.AttributionNotes = append(mod.AttributionNotes, note)
		}

		// Recent-mtime path: snapshot processes if we can. We don't have
		// the per-file mtime on the modification record itself; we need
		// to look it up from the audit. This function takes scanTimeUnix
		// and trusts the caller to have set ContentChanged/etc. correctly,
		// but we re-derive recency from the size/mode/content change as a
		// proxy: if the file was modified in this run, we capture
		// suspects unconditionally. (Fine — it's bounded to ModifiedFiles.)
		_ = scanTimeUnix
		if mod.ContentChanged || mod.ModeChanged != nil || mod.OwnerChanged != nil {
			suspects := loadProcs()
			if len(suspects) > 0 {
				mod.Suspects = suspects
				mod.AttributionNotes = append(mod.AttributionNotes,
					fmt.Sprintf("%d candidate process(es) running at scan time", len(suspects)))
			}
		}
	}
}

// isModeRelaxed reports whether the to-mode is more permissive than the
// from-mode. Used to flag permission relaxation (`0600 → 0644` on a user
// `.npmrc` is suspicious — the file became world-readable).
func isModeRelaxed(from, to string) bool {
	fp, ok1 := parseOctalMode(from)
	tp, ok2 := parseOctalMode(to)
	if !ok1 || !ok2 {
		return false
	}
	// "Relaxed" = any bit added in `to` that wasn't in `from`. That
	// catches owner-restricted → group/world-readable, and read-only →
	// writable, etc.
	return tp & ^fp != 0
}

// parseOctalMode strips a leading "0" or "0o" and parses the rest as
// octal. The mode strings we record are like "0600" or "0644".
func parseOctalMode(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	s = strings.TrimPrefix(s, "0o")
	s = strings.TrimPrefix(s, "0")
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// captureSuspects runs the platform-appropriate process-list command,
// parses it, and filters to commands matching our suspect-pattern list.
// On any error we return nil — attribution is informational, not load-bearing.
func captureSuspects(ctx context.Context, exec executor.Executor) []model.NPMRCSuspect {
	switch exec.GOOS() {
	case "windows":
		stdout, _, _, err := exec.RunWithTimeout(ctx, 5*time.Second, "tasklist", "/fo", "csv", "/nh")
		if err != nil {
			return nil
		}
		return parseTasklistCSV(stdout)
	default:
		// `ps -eo pid,user,comm,args` is portable across Linux + macOS.
		stdout, _, _, err := exec.RunWithTimeout(ctx, 5*time.Second, "ps", "-eo", "pid,user,comm,args")
		if err != nil {
			return nil
		}
		return parsePSOutput(stdout)
	}
}

// parsePSOutput parses `ps -eo pid,user,comm,args` output into a filtered
// suspect list. Header line is skipped.
func parsePSOutput(stdout string) []model.NPMRCSuspect {
	var out []model.NPMRCSuspect
	lines := strings.Split(stdout, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Format is: "  PID USER     COMM     ARGS..."
		// COMM is the short command name; ARGS is everything after it.
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		user := fields[1]
		comm := fields[2]
		// Reconstruct args: everything after fields[2]. Use the original
		// line so we keep original spacing.
		argsIdx := strings.Index(line, fields[2])
		args := ""
		if argsIdx >= 0 {
			tail := line[argsIdx:]
			// Skip past comm + whitespace.
			rest := strings.TrimSpace(strings.TrimPrefix(tail, fields[2]))
			args = rest
		}
		if !commMatchesSuspect(comm, args) {
			continue
		}
		cmd := args
		if cmd == "" {
			cmd = comm
		}
		out = append(out, model.NPMRCSuspect{PID: pid, User: user, Cmd: truncateCmd(cmd, 200)})
	}
	return out
}

// parseTasklistCSV parses Windows `tasklist /fo csv /nh` output. Format:
//
//	"image_name","PID","Session Name","Session#","Mem Usage"
//
// We only have image name + PID. Better than nothing for cross-platform.
func parseTasklistCSV(stdout string) []model.NPMRCSuspect {
	var out []model.NPMRCSuspect
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Naive CSV parse — fields are quoted, comma-separated.
		fields := splitCSVLine(line)
		if len(fields) < 2 {
			continue
		}
		image := strings.TrimSpace(fields[0])
		pidStr := strings.TrimSpace(fields[1])
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		if !commMatchesSuspect(image, "") {
			continue
		}
		out = append(out, model.NPMRCSuspect{PID: pid, Cmd: image})
	}
	return out
}

// splitCSVLine handles a single line of double-quoted, comma-separated
// values. It's not RFC 4180-complete (no escaped quotes), but tasklist
// output doesn't use those.
func splitCSVLine(line string) []string {
	var out []string
	inQuotes := false
	start := 0
	for i, r := range line {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				out = append(out, strings.Trim(line[start:i], `" `))
				start = i + 1
			}
		}
	}
	out = append(out, strings.Trim(line[start:], `" `))
	return out
}

// commMatchesSuspect returns true when the process is a plausible writer
// of a .npmrc file. The comm field is matched exactly (basename) against
// suspectCommExact; the args string is checked for substrings that
// indicate an npm-relevant invocation regardless of which interpreter
// fronts it (e.g., a `python install_npm.py` script that contains
// "npm install" in argv would surface).
func commMatchesSuspect(comm, args string) bool {
	// Strip any leading path so /usr/bin/node → "node".
	base := comm
	if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
		base = base[idx+1:]
	}
	base = strings.ToLower(strings.TrimSuffix(base, ".exe"))
	if _, ok := suspectCommExact[base]; ok {
		return true
	}
	if args != "" {
		argsLow := strings.ToLower(args)
		for _, pat := range suspectArgsContains {
			if strings.Contains(argsLow, pat) {
				return true
			}
		}
	}
	return false
}

// truncateCmd shortens a command line to a max length, ellipsizing the
// middle. Keeps both ends because trailing args (like "install <evil-pkg>")
// are often the most informative bit.
func truncateCmd(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max < 8 {
		return s[:max]
	}
	half := (max - 3) / 2
	return s[:half] + "..." + s[len(s)-half:]
}
