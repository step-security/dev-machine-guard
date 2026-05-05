package detector

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseNPMRC parses the contents of a .npmrc file into a slice of NPMRCEntry.
// It is intentionally tolerant: malformed lines are skipped without aborting
// the whole parse, so a single garbage line doesn't hide useful entries.
//
// Behavior matches the npm/ini parser's surface in the ways that matter for
// audit:
//   - `;` and `#` start a comment when they are the first non-whitespace char
//     on a line (inline `key=value ; comment` is NOT treated as a comment;
//     npm/ini retains it as part of the value).
//   - `key[]=value` denotes an array entry.
//   - URI-prefixed keys (`//host/path/:_authToken`) are valid keys.
//   - Surrounding double quotes on a value are unwrapped, but the fact that
//     the value was quoted is preserved on the entry.
//   - `${VAR}` references are NEVER expanded — preserving the literal form is
//     load-bearing for the audit (it's how we tell hardcoded secrets apart
//     from env-referenced ones).
//   - Section headers `[section]` are accepted (rare in npmrc) but ignored;
//     keys are still emitted at the top level.
//
// Returns the parsed entries. Caller decides how to attach them to a file.
func parseNPMRC(data []byte) []model.NPMRCEntry {
	var entries []model.NPMRCEntry

	// Strip UTF-8 BOM if present so the first line parses correctly.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	scanner := bufio.NewScanner(bytes.NewReader(data))
	// Allow large lines (some users base64-pin a CA into `cafile`).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		// Comment lines.
		if trimmed[0] == ';' || trimmed[0] == '#' {
			continue
		}
		// Section header — accept and ignore.
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			continue
		}
		// Find the first '=' — npm/ini uses the first one as the separator.
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			// No '=' — treat as a key with empty value (matches npm/ini).
			key := strings.TrimSpace(trimmed)
			if key == "" {
				continue
			}
			entries = append(entries, buildEntry(key, "", false, lineNum))
			continue
		}
		key := strings.TrimSpace(trimmed[:eq])
		value := strings.TrimSpace(trimmed[eq+1:])

		if key == "" {
			continue
		}

		quoted := false
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
			quoted = true
		}

		entries = append(entries, buildEntry(key, value, quoted, lineNum))
	}

	return entries
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

	display := value
	if isAuth && !isEnvRef && value != "" {
		display = redactSecret(value)
	}

	return model.NPMRCEntry{
		Key:          key,
		DisplayValue: display,
		LineNum:      lineNum,
		IsArray:      isArray,
		IsAuth:       isAuth,
		IsEnvRef:     isEnvRef,
		EnvRefVars:   envRefVars,
		ValueSHA256:  hashValue(value),
		Quoted:       quoted,
	}
}

// authKeySuffixes are the trailing key segments that mean "this is a credential."
// We compare against the suffix because npm scopes auth keys with a URI prefix:
//
//	//registry.npmjs.org/:_authToken=...
//
// so we have to look at the part after the final `:`.
var authKeySuffixes = []string{
	"_auth",
	"_authtoken",
	"_password",
	"username",
	"email",
	"cafile",
	"certfile",
	"keyfile",
	// Deprecated but still seen in the wild:
	"cert",
	"key",
}

func isAuthKey(key string) bool {
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

// envRefPattern matches ${VAR}, ${VAR:-default}, and ${VAR?error} forms.
// We only care about the VAR name; default/error sub-syntax is captured but
// not used.
var envRefPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?:[?:][^}]*)?\}`)

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
