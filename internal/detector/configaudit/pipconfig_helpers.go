package configaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
)

// urlSchemePattern matches the leading scheme of a URL-shaped string. We
// use it as a quick gate before paying for net/url.Parse.
var urlSchemePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+\-.]*://`)

// looksLikeURL returns true if the string starts with a URL scheme.
func looksLikeURL(s string) bool {
	return urlSchemePattern.MatchString(strings.TrimSpace(s))
}

// urlHasEmbeddedCreds reports whether the value contains a URL with
// `user[:pass]@host` syntax. Returns the parsed URL when true so callers
// can inspect scheme and host without re-parsing.
func urlHasEmbeddedCreds(s string) (*url.URL, bool) {
	if !looksLikeURL(s) {
		return nil, false
	}
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u == nil {
		return nil, false
	}
	if u.User == nil {
		return nil, false
	}
	return u, true
}

// urlIsHTTP returns true when the URL scheme is plain http (not https,
// not file, not anything else). Used for pip-002, pip-006, pip-008.
func urlIsHTTP(s string) bool {
	if !looksLikeURL(s) {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u == nil {
		return false
	}
	return strings.EqualFold(u.Scheme, "http")
}

// redactCredsInValue returns a safe-to-display copy of a value with any
// embedded URL credentials reduced to `user:****@host` form. Non-URL
// inputs (and URLs without credentials) are returned unchanged.
//
// We work directly on the string (not url.URL.String()) because the latter
// percent-encodes the asterisks back to %2A. Credentials live in the URL
// authority — everything between `://` and the first `/`, `?`, or `#` — and
// the userinfo is everything up to the *last* `@` in that authority. A
// well-formed URL has at most one unencoded `@`, so when a user-typed value
// concatenates several `user:pass@host` runs (e.g. a mangled index-url), the
// only real host is what follows the final `@`; everything before it is
// credential material and gets masked whole. Splitting on the first `@`
// instead would preserve the trailing runs — including a live token — in the
// "safe" output, which is exactly the leak this guards against.
func redactCredsInValue(s string) string {
	if !looksLikeURL(s) {
		return s
	}
	trimmed := strings.TrimSpace(s)
	schemeIdx := strings.Index(trimmed, "://")
	if schemeIdx < 0 {
		return s
	}
	prefix := trimmed[:schemeIdx+3] // includes "://"
	rest := trimmed[schemeIdx+3:]

	// The authority ends at the first path/query/fragment delimiter; an `@`
	// past that point belongs to the path or query, not to userinfo.
	authEnd := strings.IndexAny(rest, "/?#")
	if authEnd < 0 {
		authEnd = len(rest)
	}
	authority := rest[:authEnd]
	after := rest[authEnd:] // path/query/fragment, possibly empty

	lastAt := strings.LastIndexByte(authority, '@')
	if lastAt < 0 {
		return s // no embedded credentials
	}
	userinfo := authority[:lastAt]
	host := authority[lastAt+1:]

	// Preserve the username only when the userinfo is a single, well-formed
	// `user:pass` pair. Any extra `@` means we can't safely tell which run is
	// the username, so mask the whole thing.
	masked := "****"
	if !strings.ContainsRune(userinfo, '@') {
		if colon := strings.IndexByte(userinfo, ':'); colon >= 0 {
			masked = userinfo[:colon] + ":****"
		}
	}
	return prefix + masked + "@" + host + after
}

// hashCredential returns a stable short identifier for a credential value
// — used to recognize "the same credential" across runs without ever
// storing or re-emitting the plaintext. We hash the full raw value (incl.
// any URL prefix) and return the first 12 hex chars; that's collision-
// resistant enough for de-duplication and short enough to display.
func hashCredential(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// pipEnvNameForKey converts a pip config key (e.g. "no-build-isolation") to
// its environment-variable form (PIP_NO_BUILD_ISOLATION). Used when we
// need to check whether a key set in a file has also been overridden by
// an env var.
func pipEnvNameForKey(key string) string {
	upper := strings.ToUpper(key)
	upper = strings.ReplaceAll(upper, "-", "_")
	return "PIP_" + upper
}

// pipKeyForEnvName is the inverse of pipEnvNameForKey: PIP_INDEX_URL →
// "index-url". Returns the lower-cased, hyphenated key without the PIP_
// prefix. If the input doesn't start with PIP_, returns the input unchanged.
func pipKeyForEnvName(env string) string {
	if !strings.HasPrefix(env, "PIP_") {
		return env
	}
	tail := strings.ToLower(env[4:])
	return strings.ReplaceAll(tail, "_", "-")
}
