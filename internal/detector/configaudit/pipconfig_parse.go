package configaudit

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/model"
)

// parsePipConfig parses a pip config file into ordered sections. The format
// matches Python's RawConfigParser semantics:
//
//   - `[section]` headers introduce a new section. Entries before any
//     section header land in an implicit "" (empty-name) section, which
//     matches RawConfigParser's "DEFAULT"-but-we-store-empty convention
//     (we don't actually use DEFAULT semantics; pip never relies on them).
//   - `key = value` or `key=value` is a single-value entry.
//   - A line whose key is followed by `=` and an empty value, then one or
//     more INDENTED lines, accumulates the indented lines as the multi-
//     value list. This matches pip's documented multi-value format for
//     repeatable options like `find-links` and `trusted-host`.
//   - Comments: a line whose first non-whitespace character is `;` or `#`
//     is a comment. Pip's parser does NOT recognize inline comments
//     (matching RawConfigParser), so `key = value ; this is part of the value`
//     keeps `; this is part of the value` in the value.
//   - Blank lines are skipped.
//   - Pip does NOT interpolate `${VAR}` references. Literal `${VAR}` in a
//     value stays a literal — we propagate it verbatim.
//
// Returns the ordered list of sections. Malformed lines are skipped (we
// prefer to surface partial data rather than fail the whole audit on a
// stray byte).
func parsePipConfig(data []byte) []model.PipSection {
	// Strip BOM if present.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var sections []model.PipSection
	curSection := -1 // index into sections; -1 means no active section yet
	curEntry := -1   // index into sections[curSection].Entries; -1 means no continuation target
	pendingMulti := false

	openSection := func(name string, lineNum int) {
		sections = append(sections, model.PipSection{Name: name, LineNum: lineNum})
		curSection = len(sections) - 1
		curEntry = -1
		pendingMulti = false
	}

	// Ensure we always have a section to attach entries to. Pip files almost
	// always start with [global], but the spec doesn't require it; honor
	// pre-section entries by attaching them to an unnamed section.
	ensureSection := func(lineNum int) {
		if curSection < 0 {
			openSection("", lineNum)
		}
	}

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		// Detect indented continuation BEFORE trimming. RawConfigParser
		// treats any leading whitespace as a continuation when there's a
		// prior key with an empty value awaiting values.
		indented := len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t')
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			pendingMulti = false
			continue
		}
		// Comment line.
		if trimmed[0] == ';' || trimmed[0] == '#' {
			pendingMulti = false
			continue
		}
		// Section header.
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") && len(trimmed) >= 2 {
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			openSection(name, lineNum)
			continue
		}
		// Continuation line — attach to most recent entry's value list.
		if indented && pendingMulti && curSection >= 0 && curEntry >= 0 {
			sections[curSection].Entries[curEntry].Values = append(
				sections[curSection].Entries[curEntry].Values, trimmed,
			)
			continue
		}
		// New key/value line.
		eq := strings.IndexByte(trimmed, '=')
		if eq < 0 {
			// Could be `key:` style (configparser supports `:` too). Try
			// that as a fallback.
			eq = strings.IndexByte(trimmed, ':')
			if eq < 0 {
				pendingMulti = false
				continue
			}
		}
		key := strings.TrimSpace(trimmed[:eq])
		value := strings.TrimSpace(trimmed[eq+1:])
		if key == "" {
			pendingMulti = false
			continue
		}

		ensureSection(lineNum)
		entry := model.PipKeyValue{Key: key, LineNum: lineNum}
		if value == "" {
			// Empty inline value — likely the multi-value continuation form.
			// Leave Values empty for now; subsequent indented lines will
			// append.
			entry.Values = nil
			pendingMulti = true
		} else {
			entry.Values = []string{value}
			pendingMulti = false
		}
		sections[curSection].Entries = append(sections[curSection].Entries, entry)
		curEntry = len(sections[curSection].Entries) - 1
	}

	// Post-pass: build Display strings (used by the verbose renderer for a
	// compact one-line view of multi-values).
	for s := range sections {
		for e := range sections[s].Entries {
			ent := &sections[s].Entries[e]
			ent.Display = renderPipDisplay(ent.Key, ent.Values)
		}
	}

	return sections
}

// renderPipDisplay returns a safe-for-display string for a parsed pip
// entry. Multi-values become "v1, v2". URLs with embedded credentials are
// redacted to "user:****@host" form so the parsed view never leaks
// secrets even in pretty/HTML output. (The findings engine re-runs the
// same redaction; doing it here keeps the static view honest too.)
func renderPipDisplay(_ string, values []string) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = redactCredsInValue(v)
	}
	return strings.Join(parts, ", ")
}
