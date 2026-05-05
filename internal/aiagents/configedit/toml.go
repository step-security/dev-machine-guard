package configedit

import (
	"bytes"
	"fmt"
	"regexp"

	toml "github.com/pelletier/go-toml/v2"
)

// EnsureCodexHooksFlag returns the input bytes with `[features].codex_hooks
// = true` ensured. All bytes outside the touched line/section are
// preserved exactly. The boolean is true when the input changed.
//
// Behavior:
//   - If `codex_hooks = true` already exists under [features], no change.
//   - If `codex_hooks = false` exists under [features], only the value
//     token is rewritten to `true`.
//   - If [features] exists without the key, `codex_hooks = true` is
//     inserted on its own line immediately after the table header.
//   - If [features] does not exist, a new `[features]` table is appended
//     at the end of the file with `codex_hooks = true`.
//
// Multi-line strings (`"""..."""`, `'''...'''`) and comments are masked
// before pattern matching so that user content cannot trick the
// scanner into treating the literal text `[features]` or `codex_hooks =
// true` inside a string as a real table header or key.
//
// The patched output is validated by go-toml/v2 before return; if the
// rewrite produces invalid TOML the original bytes are returned with
// an error so the caller can abort the install with the file untouched.
func EnsureCodexHooksFlag(data []byte) ([]byte, bool, error) {
	masked := maskNonStructural(data)
	start, end, headerEnd := findFeaturesSection(masked)

	var (
		out     []byte
		changed bool
	)
	if start < 0 {
		// Append a new [features] table at end of file.
		var b bytes.Buffer
		b.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			b.WriteByte('\n')
		}
		if len(data) > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("[features]\ncodex_hooks = true\n")
		out, changed = b.Bytes(), true
	} else if loc := codexHooksLineRE.FindSubmatchIndex(masked[start:end]); loc != nil {
		valStart := start + loc[4]
		valEnd := start + loc[5]
		if string(data[valStart:valEnd]) == "true" {
			return data, false, nil
		}
		var b bytes.Buffer
		b.Write(data[:valStart])
		b.WriteString("true")
		b.Write(data[valEnd:])
		out, changed = b.Bytes(), true
	} else {
		// Insert codex_hooks = true immediately after the [features] header line.
		var b bytes.Buffer
		b.Write(data[:headerEnd])
		b.WriteString("codex_hooks = true\n")
		b.Write(data[headerEnd:])
		out, changed = b.Bytes(), true
	}

	if changed {
		probe := map[string]any{}
		if err := toml.Unmarshal(out, &probe); err != nil {
			return data, false, fmt.Errorf("configedit: patched TOML is invalid: %w", err)
		}
	}
	return out, changed, nil
}

// CodexHooksEnabled reports whether the bytes contain
// `[features].codex_hooks = true`. Multi-line strings and comments are
// masked so a literal containing the same text in a docstring is not
// misread as the real flag.
func CodexHooksEnabled(data []byte) bool {
	masked := maskNonStructural(data)
	start, end, _ := findFeaturesSection(masked)
	if start < 0 {
		return false
	}
	loc := codexHooksLineRE.FindSubmatchIndex(masked[start:end])
	if loc == nil {
		return false
	}
	return string(data[start+loc[4]:start+loc[5]]) == "true"
}

var (
	featuresHeaderRE = regexp.MustCompile(`(?m)^[ \t]*\[[ \t]*features[ \t]*\][ \t]*(#.*)?$`)
	anyHeaderRE      = regexp.MustCompile(`(?m)^[ \t]*\[\[?[^\]\n]+\]\]?[ \t]*(#.*)?$`)
	codexHooksLineRE = regexp.MustCompile(`(?m)^([ \t]*codex_hooks[ \t]*=[ \t]*)(true|false)([ \t]*(?:#.*)?)$`)
)

// findFeaturesSection scans masked TOML bytes and returns:
//   - start: byte offset of the `[features]` header line, or -1 if absent.
//   - end: byte offset of the byte AFTER the section.
//   - headerEnd: byte offset right after the newline that terminates the
//     `[features]` header line (so callers can splice in a new key
//     directly after the header).
//
// masked must be the output of maskNonStructural so multi-line strings
// and comments cannot match the regexes.
func findFeaturesSection(masked []byte) (start, end, headerEnd int) {
	loc := featuresHeaderRE.FindIndex(masked)
	if loc == nil {
		return -1, len(masked), -1
	}
	start = loc[0]
	headerEnd = loc[1]
	if headerEnd < len(masked) && masked[headerEnd] == '\n' {
		headerEnd++
	}
	rest := masked[headerEnd:]
	if next := anyHeaderRE.FindIndex(rest); next != nil {
		return start, headerEnd + next[0], headerEnd
	}
	return start, len(masked), headerEnd
}

// maskNonStructural returns a copy of data with every byte that is part
// of a comment or a string literal (including triple-quoted multi-line
// strings) replaced with a space, EXCEPT newline bytes which are kept so
// `(?m)` line anchors still work. Structural bytes (whitespace,
// brackets, bare keys, equals, true/false/numbers) are preserved.
//
// This is not a full TOML parser; it is just enough to keep our two
// regexes honest. Triple-quoted strings, single-line basic and literal
// strings, comments, and escape sequences in basic strings are
// recognized; everything else is treated as structural.
func maskNonStructural(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	pos := 0
	for pos < len(data) {
		switch data[pos] {
		case '#':
			for pos < len(data) && data[pos] != '\n' {
				out[pos] = ' '
				pos++
			}
		case '"':
			if pos+3 <= len(data) && data[pos+1] == '"' && data[pos+2] == '"' {
				pos = maskMultilineString(data, out, pos, []byte(`"""`))
			} else {
				pos = maskSingleString(data, out, pos, '"', true)
			}
		case '\'':
			if pos+3 <= len(data) && data[pos+1] == '\'' && data[pos+2] == '\'' {
				pos = maskMultilineString(data, out, pos, []byte(`'''`))
			} else {
				pos = maskSingleString(data, out, pos, '\'', false)
			}
		default:
			pos++
		}
	}
	return out
}

func maskMultilineString(data, out []byte, pos int, delim []byte) int {
	out[pos] = ' '
	out[pos+1] = ' '
	out[pos+2] = ' '
	pos += 3
	for pos < len(data) {
		if pos+3 <= len(data) && data[pos] == delim[0] && data[pos+1] == delim[1] && data[pos+2] == delim[2] {
			out[pos] = ' '
			out[pos+1] = ' '
			out[pos+2] = ' '
			return pos + 3
		}
		if data[pos] != '\n' {
			out[pos] = ' '
		}
		pos++
	}
	return pos
}

func maskSingleString(data, out []byte, pos int, quote byte, allowEscape bool) int {
	out[pos] = ' '
	pos++
	for pos < len(data) {
		if data[pos] == '\n' {
			// Unterminated string; leave the newline structural. Bail.
			return pos
		}
		if allowEscape && data[pos] == '\\' && pos+1 < len(data) {
			out[pos] = ' '
			out[pos+1] = ' '
			pos += 2
			continue
		}
		if data[pos] == quote {
			out[pos] = ' '
			return pos + 1
		}
		out[pos] = ' '
		pos++
	}
	return pos
}
