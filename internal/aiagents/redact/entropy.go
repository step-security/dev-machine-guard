package redact

import (
	"math"
	"net/url"
	"regexp"
	"strings"
)

// Entropy-based fallback redaction. Ported from agent-vault's redact.ts
// (https://github.com/botiverse/agent-vault). Runs after the rule pipeline
// to catch unknown high-entropy tokens that sit on KEY=VALUE / YAML / JSON
// shaped lines — vendor keys we don't have a prefix for, opaque cookies,
// etc. Word-like English text passes through unchanged.
//
// Tunables match the upstream defaults; a smaller minLen / lower entropy
// threshold quickly produces walls of [REDACTED] over normal log output.
const (
	entropyMinLen    = 12
	entropyMin       = 3.0
	bigramHitRateMin = 0.30
	// urlQueryEntropyMin is the threshold used by agent-api in production
	// for URL query value redaction (see redactHighEntropyQueryValues).
	// Higher than entropyMin because random-looking IDs (UUIDs, hashes)
	// are common in query strings and must NOT be over-redacted.
	urlQueryEntropyMin = 3.6
	urlQueryMinLen     = 7
)

// commonBigrams is the top ~110 English bigrams by frequency. Random
// strings score under 17%; real words and brand names (even short ones
// like "kimi") sit well above 30% because they follow English phonology.
var commonBigrams = map[string]struct{}{
	"th": {}, "he": {}, "in": {}, "er": {}, "an": {}, "re": {}, "on": {}, "en": {}, "at": {}, "es": {},
	"ed": {}, "te": {}, "ti": {}, "or": {}, "st": {}, "ar": {}, "nd": {}, "to": {}, "nt": {}, "is": {},
	"of": {}, "it": {}, "al": {}, "as": {}, "ha": {}, "ng": {}, "co": {}, "se": {}, "me": {}, "de": {},
	"le": {}, "ou": {}, "no": {}, "ne": {}, "ea": {}, "ri": {}, "ro": {}, "li": {}, "ra": {}, "io": {},
	"ic": {}, "el": {}, "la": {}, "ve": {}, "ta": {}, "ce": {}, "ma": {}, "si": {}, "om": {}, "ur": {},
	"ec": {}, "il": {}, "ge": {}, "lo": {}, "ch": {}, "so": {}, "pr": {}, "pe": {}, "fo": {}, "ca": {},
	"di": {}, "be": {}, "mo": {}, "ag": {}, "un": {}, "us": {}, "wi": {}, "hi": {}, "sh": {}, "ac": {},
	"ad": {}, "ol": {}, "ab": {}, "mi": {}, "im": {}, "id": {}, "oo": {}, "ke": {}, "ki": {}, "su": {},
	"po": {}, "pa": {}, "wa": {}, "up": {}, "do": {}, "fi": {}, "ho": {}, "da": {}, "fe": {}, "vi": {},
	"ow": {}, "am": {}, "ut": {}, "ni": {}, "lu": {}, "tr": {}, "pl": {}, "bl": {}, "sp": {}, "cr": {},
	"na": {}, "ot": {}, "ns": {}, "ll": {}, "ss": {}, "wh": {}, "ck": {}, "gh": {}, "ry": {}, "ly": {},
	"ty": {}, "ay": {}, "ey": {},
}

var (
	envAssignRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+)$`)
	yamlPairRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*\s*:\s+(.+)$`)
	jsonPairRE   = regexp.MustCompile(`"[^"]+"\s*:\s*"([^"]+)"`)
	upperOnlyRE  = regexp.MustCompile(`^[A-Z]+$`)
	digitsOnlyRE = regexp.MustCompile(`^[0-9]+$`)
	lettersRE    = regexp.MustCompile(`^[a-zA-Z]+$`)
	urlPrefixRE  = regexp.MustCompile(`^https?://`)
	pathPrefixRE = regexp.MustCompile(`^[~.]?/`)
	segmentSplit = regexp.MustCompile(`[^a-zA-Z0-9]+`)
)

// shannonEntropy returns the Shannon entropy (bits/char) of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var ent float64
	for _, c := range freq {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// looksLikeEnglish returns true if the bigram hit rate of seg meets the
// English threshold. Pure-letter inputs only.
func looksLikeEnglish(seg string) bool {
	s := strings.ToLower(seg)
	n := len(s) - 1
	if n <= 0 {
		return true
	}
	hits := 0
	for i := range n {
		if _, ok := commonBigrams[s[i:i+2]]; ok {
			hits++
		}
	}
	return float64(hits)/float64(n) >= bigramHitRateMin
}

// isWordLikeSegment classifies a single alphanumeric segment.
func isWordLikeSegment(seg string) bool {
	if len(seg) <= 3 {
		return true
	}
	if upperOnlyRE.MatchString(seg) {
		return true
	}
	if digitsOnlyRE.MatchString(seg) {
		return true
	}
	if lettersRE.MatchString(seg) {
		return looksLikeEnglish(seg)
	}
	return false
}

// looksLikeNonSecret returns true for inputs that obviously aren't credentials
// (URLs, paths, array/object literals, all-word-segment text). Used to gate
// the entropy heuristic; keeps log output readable.
func looksLikeNonSecret(s string) bool {
	if s == "" {
		return false
	}
	// Real credential tokens never contain whitespace. A YAML / JSON value
	// with a space is natural prose. The bigram heuristic alone misses some
	// short common words (e.g. "wo", "rd"), so this guard avoids walls of
	// [REDACTED] across normal sentence values.
	if strings.ContainsAny(s, " \t") {
		return true
	}
	if (strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) ||
		(strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}")) {
		return true
	}
	if urlPrefixRE.MatchString(s) {
		return true
	}
	if pathPrefixRE.MatchString(s) {
		return true
	}
	segments := segmentSplit.Split(s, -1)
	nonEmpty := segments[:0]
	for _, seg := range segments {
		if seg != "" {
			nonEmpty = append(nonEmpty, seg)
		}
	}
	if len(nonEmpty) == 0 {
		return false
	}
	for _, seg := range nonEmpty {
		if !isWordLikeSegment(seg) {
			return false
		}
	}
	return true
}

// extractValueCandidates pulls the value portion out of common config-line
// shapes. Returns nothing for comments or unrecognised lines.
func extractValueCandidates(line string) []string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return nil
	}
	var out []string
	if m := envAssignRE.FindStringSubmatch(trimmed); m != nil {
		out = append(out, m[1])
	}
	if m := yamlPairRE.FindStringSubmatch(trimmed); m != nil {
		out = append(out, m[1])
	}
	if m := jsonPairRE.FindStringSubmatch(trimmed); m != nil {
		out = append(out, m[1])
	}
	return out
}

// cleanCandidate strips surrounding quotes and trailing comma so the
// entropy/length checks see the bare token.
func cleanCandidate(c string) string {
	c = strings.TrimSpace(c)
	c = strings.TrimSuffix(c, ",")
	c = strings.TrimSpace(c)
	if len(c) >= 2 {
		first, last := c[0], c[len(c)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			c = c[1 : len(c)-1]
		}
	}
	return c
}

// urlQueryParamRE matches a single `?key=value` or `&key=value` segment
// inside a larger string. Used by urlQueryEntropyPass to scan URLs for
// opaque high-entropy values whose key name is not on the explicit list
// already handled by the `url_query_secret` rule.
var urlQueryParamRE = regexp.MustCompile(`([?&])([A-Za-z0-9_\-.]+)=([^&\s#]+)`)

// urlQueryEntropyPass scans every `?key=value` / `&key=value` segment in s
// and redacts the value if it decodes to a high-entropy token. Ported from
// agent-api's redactQueryParams + redactHighEntropyQueryValues. Provides
// fallback coverage for opaque tokens whose param name is not on the
// explicit credential list (e.g. `?ref=…`, `?nonce=…`, vendor-specific
// names). Idempotent — `[REDACTED]` is bigram-rich and below the threshold,
// and we early-out on values that already contain it.
func urlQueryEntropyPass(s string) string {
	if !strings.ContainsRune(s, '?') {
		return s
	}
	return urlQueryParamRE.ReplaceAllStringFunc(s, func(match string) string {
		m := urlQueryParamRE.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		sep, key, val := m[1], m[2], m[3]
		if strings.Contains(val, Placeholder) || val == Placeholder {
			return match
		}
		if len(val) <= urlQueryMinLen {
			return match
		}
		decoded, err := url.QueryUnescape(val)
		if err != nil {
			decoded = val
		}
		if shannonEntropy(decoded) < urlQueryEntropyMin {
			return match
		}
		if looksLikeNonSecret(decoded) {
			return match
		}
		return sep + key + "=" + Placeholder
	})
}

// entropyPass scans s line by line and replaces high-entropy candidate
// values with Placeholder. Non-config lines, comments, and lines already
// containing Placeholder are skipped to keep the pass cheap and idempotent.
func entropyPass(s string) string {
	if !strings.ContainsAny(s, "=:") {
		return s
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		if strings.Contains(line, Placeholder) {
			continue
		}
		candidates := extractValueCandidates(line)
		for _, raw := range candidates {
			cleaned := cleanCandidate(raw)
			if len(cleaned) < entropyMinLen {
				continue
			}
			if cleaned == Placeholder {
				continue
			}
			if shannonEntropy(cleaned) < entropyMin {
				continue
			}
			if looksLikeNonSecret(cleaned) {
				continue
			}
			lines[i] = strings.Replace(lines[i], cleaned, Placeholder, 1)
		}
	}
	return strings.Join(lines, "\n")
}
