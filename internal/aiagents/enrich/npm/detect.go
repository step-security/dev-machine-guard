// Package npm classifies and enriches npm-ecosystem package manager activity
// observed in shell commands. Detection is pure; enrichment may shell out to
// npm/pnpm/yarn/bun under a caller-provided context.
package npm

import (
	"strings"

	"github.com/google/shlex"
	"github.com/step-security/dev-machine-guard/internal/aiagents/event"
)

// Manager identifies a supported package manager.
type Manager string

const (
	NPM  Manager = "npm"
	NPX  Manager = "npx"
	PNPM Manager = "pnpm"
	Yarn Manager = "yarn"
	Bun  Manager = "bun"
)

// Detection summarizes which manager and command kind were detected.
type Detection struct {
	Manager     Manager
	CommandKind string // install | uninstall | exec | publish | other
	Args        []string
}

// Detect parses cmd and returns the package-manager classification, or nil.
// Compound shell commands joined by &&, ||, ;, |, &, or newline are split into
// segments and each is classified independently; the strongest detection wins
// (install > uninstall > publish > audit > exec > other).
func Detect(cmd string) *Detection {
	segments := splitShellSegments(cmd)
	if len(segments) == 0 {
		segments = []string{cmd}
	}
	var best *Detection
	for _, seg := range segments {
		d := detectSegment(seg)
		if d == nil {
			continue
		}
		if best == nil || kindRank(d.CommandKind) > kindRank(best.CommandKind) {
			best = d
		}
	}
	return best
}

func detectSegment(cmd string) *Detection {
	tokens, err := shlex.Split(cmd)
	if err != nil || len(tokens) == 0 {
		// Fall back to whitespace split; shlex fails on unbalanced quotes.
		tokens = strings.Fields(cmd)
		if len(tokens) == 0 {
			return nil
		}
	}
	for len(tokens) > 0 && (strings.Contains(tokens[0], "=") || tokens[0] == "env") {
		tokens = tokens[1:]
	}
	if len(tokens) == 0 {
		return nil
	}
	bin := tokens[0]
	if idx := strings.LastIndexByte(bin, '/'); idx >= 0 {
		bin = bin[idx+1:]
	}
	mgr, ok := managerFromBinary(bin)
	if !ok {
		return nil
	}
	args := tokens[1:]
	return &Detection{
		Manager:     mgr,
		CommandKind: classifyKind(mgr, args),
		Args:        args,
	}
}

// splitShellSegments splits cmd at unquoted shell control operators
// (&&, ||, ;, |, &, newline). Single and double quotes are respected;
// backslash escapes the next byte outside single quotes.
func splitShellSegments(cmd string) []string {
	var (
		segments []string
		cur      strings.Builder
		inSingle bool
		inDouble bool
	)
	flush := func() {
		s := strings.TrimSpace(cur.String())
		if s != "" {
			segments = append(segments, s)
		}
		cur.Reset()
	}
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		if !inSingle && c == '\\' && i+1 < len(cmd) {
			cur.WriteByte(c)
			cur.WriteByte(cmd[i+1])
			i++
			continue
		}
		if !inDouble && c == '\'' {
			inSingle = !inSingle
			cur.WriteByte(c)
			continue
		}
		if !inSingle && c == '"' {
			inDouble = !inDouble
			cur.WriteByte(c)
			continue
		}
		if !inSingle && !inDouble {
			switch c {
			case '\n', ';':
				flush()
				continue
			case '&':
				if i+1 < len(cmd) && cmd[i+1] == '&' {
					flush()
					i++
					continue
				}
				flush()
				continue
			case '|':
				if i+1 < len(cmd) && cmd[i+1] == '|' {
					flush()
					i++
					continue
				}
				flush()
				continue
			}
		}
		cur.WriteByte(c)
	}
	flush()
	return segments
}

func kindRank(kind string) int {
	switch kind {
	case "install":
		return 6
	case "uninstall":
		return 5
	case "publish":
		return 4
	case "audit":
		return 3
	case "exec":
		return 2
	default:
		return 1
	}
}

func managerFromBinary(bin string) (Manager, bool) {
	switch bin {
	case "npm":
		return NPM, true
	case "npx":
		return NPX, true
	case "pnpm", "pnpx":
		return PNPM, true
	case "yarn":
		return Yarn, true
	case "bun", "bunx":
		return Bun, true
	}
	return "", false
}

func classifyKind(mgr Manager, args []string) string {
	var sub string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			continue
		}
		sub = strings.ToLower(a)
		break
	}
	if sub == "" {
		switch mgr {
		case PNPM, Yarn, Bun:
			return "install"
		}
		return "other"
	}
	if isInstallCommand(mgr, sub) {
		return "install"
	}
	if isUninstallCommand(mgr, sub) {
		return "uninstall"
	}
	switch sub {
	case "exec", "run", "x", "dlx":
		return "exec"
	case "publish":
		return "publish"
	case "audit":
		return "audit"
	}
	if mgr == NPX || mgr == Bun {
		return "exec"
	}
	return "other"
}

func isInstallCommand(mgr Manager, sub string) bool {
	switch mgr {
	case NPM:
		return sub == "i" || sub == "install" || sub == "ci" || sub == "add"
	case PNPM:
		return sub == "i" || sub == "install" || sub == "ci" || sub == "add"
	case Yarn:
		return sub == "install" || sub == "add"
	case Bun:
		return sub == "i" || sub == "install" || sub == "add"
	}
	return false
}

func isUninstallCommand(mgr Manager, sub string) bool {
	switch mgr {
	case NPM:
		return sub == "uninstall" || sub == "remove" || sub == "rm" || sub == "un"
	case PNPM:
		return sub == "remove" || sub == "rm" || sub == "uninstall" || sub == "un"
	case Yarn:
		return sub == "remove"
	case Bun:
		return sub == "remove" || sub == "rm" || sub == "uninstall" || sub == "un"
	}
	return false
}

func confidence(m Manager) string {
	switch m {
	case NPM, NPX:
		return "high"
	case PNPM, Yarn:
		return "medium"
	case Bun:
		return "low"
	}
	return "low"
}

// EnrichResult is a thin alias used by the hook runtime.
type EnrichResult = event.PackageManagerInfo
