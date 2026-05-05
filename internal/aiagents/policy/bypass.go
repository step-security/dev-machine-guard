package policy

import (
	"strings"

	"github.com/google/shlex"
)

// ParsedCommand is the pre-policy view of a shell argv: the leading
// `KEY=VAL` env, the package manager binary, the residual args, plus the
// flags we care about.
type ParsedCommand struct {
	InlineEnv      map[string]string
	Binary         string
	Args           []string
	RegistryFlag   string
	UserconfigFlag string
	// ConfigOp is "" unless argv looks like `<pm> config <set|delete|edit> ...`.
	ConfigOp    string
	ConfigKey   string
	ConfigValue string
}

// ParseShell tokenizes cmd and pulls out the pieces the policy evaluator
// cares about. Unknown commands return Binary="" and the caller should
// treat the parse as a no-op.
func ParseShell(cmd string) ParsedCommand {
	tokens, err := shlex.Split(cmd)
	if err != nil || len(tokens) == 0 {
		tokens = strings.Fields(cmd)
		if len(tokens) == 0 {
			return ParsedCommand{}
		}
	}
	out := ParsedCommand{InlineEnv: map[string]string{}}
	for len(tokens) > 0 {
		t := tokens[0]
		if t == "env" {
			tokens = tokens[1:]
			continue
		}
		if eq := strings.IndexByte(t, '='); eq > 0 && !strings.HasPrefix(t, "-") {
			key := t[:eq]
			if isShellIdent(key) {
				out.InlineEnv[key] = t[eq+1:]
				tokens = tokens[1:]
				continue
			}
		}
		break
	}
	if len(tokens) == 0 {
		return out
	}
	bin := tokens[0]
	if idx := strings.LastIndexByte(bin, '/'); idx >= 0 {
		bin = bin[idx+1:]
	}
	out.Binary = bin
	out.Args = tokens[1:]

	out.RegistryFlag = extractFlagValue(out.Args, "--registry")
	out.UserconfigFlag = extractFlagValue(out.Args, "--userconfig")

	if op, key, val, ok := extractConfigOp(out.Args); ok {
		out.ConfigOp = op
		out.ConfigKey = key
		out.ConfigValue = val
	}
	return out
}

// extractFlagValue finds `--flag=value` or `--flag value` and returns value.
func extractFlagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
		if v, ok := strings.CutPrefix(a, flag+"="); ok {
			return v
		}
	}
	return ""
}

// extractConfigOp recognizes `config set <k> <v>`, `config delete <k>`, or
// `config edit`. Returns ("set"|"delete"|"edit", key, value, true).
// pnpm uses `pnpm config set`, yarn uses `yarn config set`, etc.
func extractConfigOp(args []string) (op, key, value string, ok bool) {
	// Skip leading flags before the "config" subcommand.
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		// Skip values for known value-bearing flags.
		if eq := strings.IndexByte(args[i], '='); eq < 0 {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
		}
		i++
	}
	if i >= len(args) || args[i] != "config" {
		return "", "", "", false
	}
	i++
	if i >= len(args) {
		return "", "", "", false
	}
	switch args[i] {
	case "set":
		if i+2 < len(args) {
			return "set", args[i+1], args[i+2], true
		}
		if i+1 < len(args) {
			return "set", args[i+1], "", true
		}
	case "delete", "rm":
		if i+1 < len(args) {
			return "delete", args[i+1], "", true
		}
	case "edit":
		return "edit", "", "", true
	}
	return "", "", "", false
}

func isShellIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}
