package rules

import (
	"errors"
	"regexp"
	"strings"
)

// compiledGlob is a validated, ready-to-match file glob.
//
//   - Relative globs (no leading "/", no drive/UNC root) match a candidate's
//     path *relative to a search root*, at any depth via "**/". They are
//     pre-compiled to an anchored RE2 (re).
//   - Absolute globs (leading "/", a Windows drive like "C:/", or a UNC root
//     like "//host/share") name an exact path and are resolved at scan time
//     via the executor's Glob (filepath.Glob semantics); re is nil.
//
// raw is the original glob string, echoed back as matched_glob in findings.
type compiledGlob struct {
	raw      string
	absolute bool
	re       *regexp.Regexp
}

// compileGlob validates a glob and, for relative globs, compiles it to an
// anchored RE2. Globs are forward-slash only, must not contain a backslash, and
// must not contain "." or ".." path segments.
func compileGlob(glob string) (compiledGlob, error) {
	if err := validateGlob(glob); err != nil {
		return compiledGlob{}, err
	}
	cg := compiledGlob{raw: glob, absolute: isAbsoluteGlob(glob)}
	if cg.absolute {
		return cg, nil
	}
	re, err := globToRegex(glob)
	if err != nil {
		return compiledGlob{}, err
	}
	cg.re = re
	return cg, nil
}

// validateGlob enforces the structural constraints from the authoring contract.
func validateGlob(glob string) error {
	if strings.TrimSpace(glob) == "" {
		return errors.New("empty glob")
	}
	if strings.Contains(glob, `\`) {
		return errors.New("glob must use forward slashes, not backslashes")
	}
	for _, seg := range strings.Split(glob, "/") {
		if seg == "." || seg == ".." {
			return errors.New(`glob must not contain "." or ".." segments`)
		}
	}
	return nil
}

// isAbsoluteGlob reports whether a glob names an absolute path: a leading "/",
// a UNC root ("//host/..."), or a Windows drive root ("C:/...").
func isAbsoluteGlob(glob string) bool {
	if strings.HasPrefix(glob, "/") {
		return true
	}
	if len(glob) >= 3 && isDriveLetter(glob[0]) && glob[1] == ':' && glob[2] == '/' {
		return true
	}
	return false
}

func isDriveLetter(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// globToRegex converts a relative glob to an anchored RE2 that is matched
// against a forward-slash path relative to a search root:
//
//	**/  → (?:.*/)?   (zero or more leading path segments)
//	**   → .*         (any run, including separators)
//	*    → [^/]*      (within a single segment)
//	?    → [^/]       (one non-separator char)
//
// All other characters are matched literally.
func globToRegex(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(glob); {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				if i+2 < len(glob) && glob[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 3
				} else {
					b.WriteString(".*")
					i += 2
				}
			} else {
				b.WriteString("[^/]*")
				i++
			}
		case '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
			i++
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}
