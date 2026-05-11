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
func Detect(cmd string) *Detection {
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
