package configaudit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parseYarnClassic parses a yarn v1 `.yarnrc`: `key value` per line with
// optional double-quoted key and value, `#` / `;` line comments, URI-prefixed
// keys like `//npm.example.com/:_authToken`. Tolerant of malformed lines — they
// surface as best-effort entries rather than aborting the parse.
func parseYarnClassic(data []byte) []model.YarnEntry {
	var entries []model.YarnEntry

	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if trimmed[0] == '#' || trimmed[0] == ';' {
			continue
		}

		// yarn v1 uses whitespace as the key/value separator; the value may
		// be quoted. Split on the first run of whitespace.
		key, value, quoted := splitYarnClassicLine(trimmed)
		if key == "" {
			continue
		}
		entries = append(entries, buildYarnEntry(key, value, quoted, lineNum))
	}

	return entries
}

// splitYarnClassicLine returns (key, unquoted-value, was-quoted). Keys and
// values may be JSON strings, as `yarn config set` writes them for keys
// holding `:` (`"//npm.example.com/:_authToken" abc`); an unterminated quote
// keeps the raw text.
func splitYarnClassicLine(line string) (string, string, bool) {
	key, rest, quotedKey := yarnClassicQuoted(line)
	if !quotedKey {
		idx := strings.IndexAny(line, " \t")
		if idx < 0 {
			return line, "", false
		}
		key, rest = line[:idx], line[idx:]
	}
	rest = strings.TrimLeft(rest, " \t")
	if rest == "" {
		return key, "", false
	}
	if value, _, ok := yarnClassicQuoted(rest); ok {
		return key, value, true
	}
	return key, rest, false
}

// yarnClassicQuoted reads a leading JSON string token and returns what
// follows it.
func yarnClassicQuoted(s string) (tok, rest string, ok bool) {
	if !strings.HasPrefix(s, `"`) {
		return "", "", false
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			if json.Unmarshal([]byte(s[:i+1]), &tok) != nil {
				return "", "", false
			}
			return tok, s[i+1:], true
		}
	}
	return "", "", false
}

// yarnClassicAuthSuffixes match the segment after the final `:` so
// URI-prefixed keys like `//npm.example.com/:_authToken` resolve correctly.
var yarnClassicAuthSuffixes = []string{
	"_auth",
	"_authtoken",
	"_password",
	"npmauthtoken",
}

func isYarnClassicAuthKey(key string) bool {
	suffix := key
	if idx := strings.LastIndex(key, ":"); idx >= 0 {
		suffix = key[idx+1:]
	}
	suffix = strings.ToLower(suffix)
	for _, s := range yarnClassicAuthSuffixes {
		if suffix == s {
			return true
		}
	}
	return false
}

func buildYarnEntry(key, value string, quoted bool, lineNum int) model.YarnEntry {
	isAuth := isYarnClassicAuthKey(key) || isYarnBerryAuthKey(key)
	envRefVars, isEnvRef := extractEnvRefs(value)
	display, hasLiteral := redactValue(value, isAuth)

	return model.YarnEntry{
		Key:            key,
		DisplayValue:   display,
		LineNum:        lineNum,
		IsAuth:         isAuth,
		IsEnvRef:       isEnvRef,
		EnvRefVars:     envRefVars,
		ValueSHA256:    hashValue(value),
		Quoted:         quoted,
		HasLiteralAuth: hasLiteral,
	}
}
