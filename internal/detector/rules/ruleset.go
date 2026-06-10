package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// hardMaxFileSize is the engine's absolute ceiling on the bytes read from any
// single file. A rule's max_file_size is clamped to this; 0/omitted ⇒ this cap.
const hardMaxFileSize = 8 << 20 // 8 MiB

// Condition kinds. Only two exist, and both yield a boolean only — no matched
// text is ever captured (privacy model).
const (
	condKindRegex  = "regex"
	condKindSHA256 = "sha256"
)

// RuleSet is the agent-facing rule bundle (the fixed wire contract, verbatim,
// with no schema version field). It is produced by the backend's run-config
// endpoint and consumed by the engine after Prepare().
type RuleSet struct {
	Rules []Rule `json:"rules"`
}

// Rule is one detection rule: where to look (FileGlobs + a MaxFileSize cost
// guard) and what to match (Groups of boolean conditions). Revision is the
// opaque, backend-assigned rule revision that the agent echoes back but
// never interprets. No severity/category/title/campaign/description lives on a
// rule — that is backend-only metadata.
type Rule struct {
	ID          string           `json:"id"`
	Revision    string           `json:"revision,omitempty"`
	FileGlobs   []string         `json:"file_globs"`
	MaxFileSize int64            `json:"max_file_size"`
	Groups      []ConditionGroup `json:"groups,omitempty"`

	globs []compiledGlob // set by Prepare; not serialized
}

// ConditionGroup is one signature set (e.g. one attack). A rule can screen one
// file for several attacks via multiple groups.
type ConditionGroup struct {
	ID         string      `json:"id"`
	Conditions []Condition `json:"conditions"`
}

// Condition is a single boolean test against a file. Negate inverts it.
// Mandatory conditions gate whether the file is reported at all: a group is
// "satisfied" only when all its mandatory conditions match, and a file with
// groups is reported only if at least one group is satisfied. Optional
// conditions (the default) only influence confidence. Use mandatory conditions
// for rules that target files which legitimately exist (e.g. injected config),
// and all-optional conditions for rules whose target file should never exist.
type Condition struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`    // "regex" | "sha256"
	Pattern   string `json:"pattern"` // RE2 source (regex) | 64-char hex SHA-256 (sha256)
	Negate    bool   `json:"negate,omitempty"`
	Mandatory bool   `json:"mandatory,omitempty"`

	re *regexp.Regexp // compiled RE2 for kind=regex; set by Prepare
}

// Prepare validates and compiles the ruleset in place. Any error means the
// whole bundle is rejected (the caller scans nothing this run). It is
// pure: no I/O, no network. Enforces non-empty unique rule ids, ≥1 file glob,
// unique group ids per rule and condition ids per group, glob validity,
// RE2-compilable regexes, 64-char-hex sha256 patterns, and clamps max_file_size
// to the hard cap.
func (rs *RuleSet) Prepare() error {
	seenRules := make(map[string]bool, len(rs.Rules))
	for i := range rs.Rules {
		r := &rs.Rules[i]

		id := strings.TrimSpace(r.ID)
		if id == "" {
			return fmt.Errorf("rule[%d]: empty id", i)
		}
		if seenRules[id] {
			return fmt.Errorf("rule %q: duplicate id", id)
		}
		seenRules[id] = true

		if len(r.FileGlobs) == 0 {
			return fmt.Errorf("rule %q: at least one file_glob is required", id)
		}
		r.globs = r.globs[:0]
		for _, g := range r.FileGlobs {
			cg, err := compileGlob(g)
			if err != nil {
				return fmt.Errorf("rule %q: glob %q: %w", id, g, err)
			}
			r.globs = append(r.globs, cg)
		}

		// Clamp the cost guard to the hard cap; 0/omitted/negative ⇒ the cap.
		if r.MaxFileSize <= 0 || r.MaxFileSize > hardMaxFileSize {
			r.MaxFileSize = hardMaxFileSize
		}

		seenGroups := make(map[string]bool, len(r.Groups))
		for gi := range r.Groups {
			grp := &r.Groups[gi]
			gid := strings.TrimSpace(grp.ID)
			if gid == "" {
				return fmt.Errorf("rule %q: group[%d]: empty id", id, gi)
			}
			if seenGroups[gid] {
				return fmt.Errorf("rule %q: group %q: duplicate id", id, gid)
			}
			seenGroups[gid] = true

			if len(grp.Conditions) == 0 {
				return fmt.Errorf("rule %q group %q: at least one condition is required", id, gid)
			}
			seenConds := make(map[string]bool, len(grp.Conditions))
			for ci := range grp.Conditions {
				c := &grp.Conditions[ci]
				cid := strings.TrimSpace(c.ID)
				if cid == "" {
					return fmt.Errorf("rule %q group %q: condition[%d]: empty id", id, gid, ci)
				}
				if seenConds[cid] {
					return fmt.Errorf("rule %q group %q: condition %q: duplicate id", id, gid, cid)
				}
				seenConds[cid] = true

				switch c.Kind {
				case condKindRegex:
					re, err := regexp.Compile(c.Pattern)
					if err != nil {
						return fmt.Errorf("rule %q group %q condition %q: bad regex: %w", id, gid, cid, err)
					}
					c.re = re
				case condKindSHA256:
					if !isHex64(c.Pattern) {
						return fmt.Errorf("rule %q group %q condition %q: sha256 must be 64 hex chars", id, gid, cid)
					}
				default:
					return fmt.Errorf("rule %q group %q condition %q: unknown kind %q", id, gid, cid, c.Kind)
				}
			}
		}
	}
	return nil
}

// isHex64 reports whether s is exactly 64 hexadecimal characters.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		case c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
