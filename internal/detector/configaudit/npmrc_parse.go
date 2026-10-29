package configaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseNPMRC parses the contents of a .npmrc file into a slice of NPMRCEntry.
// It is intentionally tolerant: malformed lines are skipped without aborting
// the whole parse, so a single garbage line doesn't hide useful entries.
//
// Line handling follows npm's bundled ini parser:
//   - `;` and `#` start a comment when they are the first non-whitespace char
//     on a line; elsewhere an unescaped `;` or `#` ends an unquoted value.
//   - A value wrapped in matching quotes is unwrapped (JSON-decoded when it
//     is valid JSON) and keeps comment characters.
//   - A key without `=` has the value `true`.
//   - `key[]=value` denotes an array entry.
//   - `${VAR}` references are NEVER expanded — preserving the literal form is
//     load-bearing for the audit (it's how we tell hardcoded secrets apart
//     from env-referenced ones).
//   - Keys under a `[section]` header become a nested object in npm, not
//     top-level settings, so they are not emitted; the returned limitation
//     says the file has settings npm won't apply as written.
//
// Entries stay in physical order with their line numbers, duplicates included.
func parseNPMRC(data []byte) (entries []model.NPMRCEntry, limitation string) {
	// Strip UTF-8 BOM if present so the first line parses correctly.
	text := string(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
	text = strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(text)
	inSection := false
	for i, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed[0] == ';' || trimmed[0] == '#' {
			continue
		}
		if iniSectionPattern.MatchString(line) {
			inSection = true
			limitation = "sectioned settings not applied"
			continue
		}
		rawKey, rawValue, hasValue := strings.Cut(line, "=")
		key, _ := iniUnsafe(rawKey)
		if key == "" || inSection {
			continue
		}
		value, quoted := "true", false
		if hasValue {
			value, quoted = iniUnsafe(rawValue)
		}
		entries = append(entries, buildEntry(key, value, quoted, i+1))
	}
	return entries, limitation
}

var iniSectionPattern = regexp.MustCompile(`^\[[^\]]*\]\s*$`)

// iniUnsafe decodes one key or value the way npm's ini parser does.
func iniUnsafe(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		inner := s
		if s[0] == '\'' {
			inner = s[1 : len(s)-1]
		}
		var decoded string
		if json.Unmarshal([]byte(inner), &decoded) == nil {
			return decoded, true
		}
		return inner, true
	}
	var b strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			if r != '\\' && r != ';' && r != '#' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
			escaped = false
		case r == ';' || r == '#':
			return strings.TrimSpace(b.String()), false
		case r == '\\':
			escaped = true
		default:
			b.WriteRune(r)
		}
	}
	if escaped {
		b.WriteByte('\\')
	}
	return strings.TrimSpace(b.String()), false
}

// buildEntry classifies a key/value into an NPMRCEntry, populating the
// security-relevant flags (auth, env-ref) and a safe-to-display value.
func buildEntry(key, value string, quoted bool, lineNum int) model.NPMRCEntry {
	isArray := false
	if strings.HasSuffix(key, "[]") {
		isArray = true
		key = key[:len(key)-2]
	}

	isAuth := isAuthKey(key)
	envRefVars, isEnvRef := extractEnvRefs(value)
	display, hasLiteral := redactValue(value, isAuth)

	return model.NPMRCEntry{
		Key:            key,
		DisplayValue:   display,
		LineNum:        lineNum,
		IsArray:        isArray,
		IsAuth:         isAuth,
		IsEnvRef:       isEnvRef,
		EnvRefVars:     envRefVars,
		ValueSHA256:    hashValue(value),
		Quoted:         quoted,
		HasLiteralAuth: hasLiteral,
	}
}

// authKeySuffixes are the trailing key segments that mean "this is a credential."
// We compare against the suffix because npm scopes auth keys with a URI prefix:
//
//	//registry.npmjs.org/:_authToken=...
//
// so we have to look at the part after the final `:`. `key` holds inline
// private-key PEM content. The other TLS keys (`cafile`, `certfile`,
// `keyfile`, `cert`) are intentionally NOT included — they hold file paths
// or public certificates, and redacting them makes the audit less useful
// while mislabeling them as auth material.
var authKeySuffixes = []string{
	"_auth",
	"_authtoken",
	"_password",
	"username",
	"email",
	"key",
}

func isAuthKey(key string) bool {
	// pnpm's structured `_auth` YAML map flattens to `_auth.<registry>...`.
	if strings.HasPrefix(key, "_auth.") {
		return true
	}
	// Compare against the segment after the final `:` (URI-scoped keys) or
	// against the full key (non-scoped legacy form).
	suffix := key
	if idx := strings.LastIndex(key, ":"); idx >= 0 {
		suffix = key[idx+1:]
	}
	suffix = strings.ToLower(suffix)
	for _, s := range authKeySuffixes {
		if suffix == s {
			return true
		}
	}
	return false
}

// envRefPattern matches ${VAR}, ${VAR?}, ${VAR-default}, ${VAR:-default}
// and ${VAR?error} forms. Group 2 holds any operator and default text; a
// default is literal material, so redaction masks it while keeping VAR.
var envRefPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)([?:-][^}]*)?\}`)

func extractEnvRefs(value string) ([]string, bool) {
	matches := envRefPattern.FindAllStringSubmatch(value, -1)
	if len(matches) == 0 {
		return nil, false
	}
	seen := make(map[string]struct{}, len(matches))
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		name := m[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, true
}

// redactValue returns the display form of a value plus whether literal
// credential material was masked. Auth values mask every literal span and
// keep env-reference names; other values only lose URL userinfo.
func redactValue(value string, isAuth bool) (string, bool) {
	if !isAuth || value == "" {
		return redactURLUserinfo(value)
	}
	locs := envRefPattern.FindAllStringSubmatchIndex(value, -1)
	if len(locs) == 0 {
		return redactSecret(value), true
	}
	var b strings.Builder
	literal := false
	mask := func(s string) {
		if strings.IndexFunc(s, isAlnum) >= 0 {
			b.WriteString("***")
			literal = true
		} else {
			b.WriteString(s)
		}
	}
	last := 0
	for _, m := range locs {
		mask(value[last:m[0]])
		ref := value[m[0]:m[1]]
		if m[4] >= 0 {
			suffix := value[m[4]:m[5]]
			op := suffix[:len(suffix)-len(strings.TrimLeft(suffix, "?:-"))]
			if len(op) < len(suffix) {
				ref = value[m[0]:m[4]] + op + "***}"
				literal = true
			}
		}
		b.WriteString(ref)
		last = m[1]
	}
	mask(value[last:])
	return b.String(), literal
}

// The userinfo runs to the last `@` before the path, as URL parsers read
// it, so an unencoded `@` in a password is still masked.
var urlUserinfoPattern = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)([^/?#\s]+)@`)

// redactURLUserinfo masks credentials embedded in any URL inside v, even
// when another part of the value is an env reference. Userinfo made only of
// env references stays visible.
func redactURLUserinfo(v string) (string, bool) {
	literal := false
	out := urlUserinfoPattern.ReplaceAllStringFunc(v, func(m string) string {
		sub := urlUserinfoPattern.FindStringSubmatch(m)
		if _, masked := redactValue(sub[2], true); !masked {
			return m
		}
		literal = true
		return sub[1] + "***@"
	})
	return out, literal
}

func isAlnum(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// redactSecret returns a safe-to-display form of an auth value. We keep the
// last 4 characters when the secret is long enough to make rotation tracking
// useful; for short secrets we collapse to `***` so we never leak meaningful
// material. The full value is never returned.
func redactSecret(v string) string {
	if len(v) <= 8 {
		return "***"
	}
	return "***" + v[len(v)-4:]
}

// hashValue returns the hex SHA-256 of a value. We hash the raw value (before
// redaction) so two different secrets produce different hashes — that's what
// lets the change-tracking phase notice rotation without ever storing the
// plaintext.
func hashValue(v string) string {
	if v == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}
