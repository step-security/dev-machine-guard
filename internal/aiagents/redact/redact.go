// Package redact removes likely secrets from strings and JSON-shaped values
// before they are written to disk or sent over the wire. Redaction MUST
// run before every write, including error logs.
package redact

import (
	"regexp"
	"strings"
)

// Placeholder is what every matched secret is replaced with.
const Placeholder = "[REDACTED]"

// rule pairs a compiled regex with the submatch group whose content should be
// replaced. group == 0 redacts the entire match.
type rule struct {
	name  string
	re    *regexp.Regexp
	group int
}

// rules is intentionally conservative. Adding too aggressive a rule risks
// turning normal logs into a wall of [REDACTED] and hiding genuine signal.
// Every rule here exists to satisfy the redaction regression tests.
var rules = []rule{
	// PEM-encoded private keys: redact the whole block. The optional
	// ` BLOCK` suffix covers PGP armor (`BEGIN PGP PRIVATE KEY BLOCK`)
	// alongside RSA / OPENSSH / PKCS#8 ("BEGIN PRIVATE KEY") variants.
	{
		name: "private_key_block",
		re:   regexp.MustCompile(`(?s)-----BEGIN[ A-Z]*PRIVATE KEY( BLOCK)?-----.*?-----END[ A-Z]*PRIVATE KEY( BLOCK)?-----`),
	},
	// AWS access key IDs: stable prefix + 16 base32-ish chars.
	{
		name: "aws_access_key_id",
		re:   regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b`),
	},
	// GitHub classic tokens (PAT, OAuth, server-to-server, refresh).
	// The header-style rule below covers `github_pat_*` fine-grained
	// tokens, which use a different prefix shape.
	{
		name: "github_token",
		re:   regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}\b`),
	},
	// GitHub fine-grained PAT: `github_pat_<22>_<59>` per GitHub docs.
	// The inner `_` between the two segments is matched by the
	// underscore in the character class.
	{
		name: "github_fine_grained_pat",
		re:   regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
	},
	// Slack tokens.
	{
		name: "slack_token",
		re:   regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),
	},
	// Authorization: Bearer <token>.
	{
		name:  "bearer_token",
		re:    regexp.MustCompile(`(?i)(authorization\s*[:=]\s*"?\s*bearer\s+)([A-Za-z0-9._\-+/=]{8,})`),
		group: 2,
	},
	// Standalone "Bearer <token>" outside of an Authorization header.
	{
		name:  "bearer_inline",
		re:    regexp.MustCompile(`(?i)\b(bearer\s+)([A-Za-z0-9._\-+/=]{16,})`),
		group: 2,
	},
	// npm auth tokens in .npmrc style.
	{
		name:  "npm_auth_token",
		re:    regexp.MustCompile(`(?i)(_authToken\s*=\s*)([^\s"]+)`),
		group: 2,
	},
	{
		name:  "npm_auth",
		re:    regexp.MustCompile(`(?i)(\b_auth\s*=\s*)([^\s"]+)`),
		group: 2,
	},
	// AWS secret access key style assignments.
	{
		name:  "aws_secret_access_key",
		re:    regexp.MustCompile(`(?i)(aws_secret_access_key\s*[:=]\s*"?)([A-Za-z0-9/+=]{30,})`),
		group: 2,
	},
	// Generic KEY=value assignments for common secret-bearing names.
	{
		name:  "secret_assignment",
		re:    regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY))\s*[:=]\s*("?)([^\s"'#]+)`),
		group: 3,
	},
	// JSON-shaped key/value pairs, e.g. "api_key": "abc".
	{
		name:  "secret_json_field",
		re:    regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization)"\s*:\s*")([^"]+)`),
		group: 2,
	},
	// URL userinfo: https://user:pass@host/... — redact the userinfo
	// segment (everything between scheme:// and @). Matches any scheme.
	{
		name:  "url_userinfo",
		re:    regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://)([^\s/@]+)@`),
		group: 2,
	},
	// URL query-string credentials. Param name is matched with an
	// optional `<prefix>_` so suffix variants (access_token,
	// refresh_token, id_token, client_secret, jwt_signature, ...) are
	// covered. OAuth `code` and `state` are short-lived but
	// credential-grade during their window.
	{
		name:  "url_query_secret",
		re:    regexp.MustCompile(`(?i)([?&](?:[a-z0-9_-]*_)?(?:token|secret|signature|password|passwd|api[_-]?key|apikey|auth|sig|code|state)=)([^&\s#]+)`),
		group: 2,
	},
}

// Sensitive path patterns. Callers consult these to decide whether a
// payload references credential material.
var sensitivePathREs = []*regexp.Regexp{
	regexp.MustCompile(`(^|/)\.env(\.|$)`),
	regexp.MustCompile(`(^|/)\.env$`),
	regexp.MustCompile(`(^|/)secrets/`),
	regexp.MustCompile(`\.pem$`),
	regexp.MustCompile(`\.key$`),
	regexp.MustCompile(`\.p12$`),
	regexp.MustCompile(`(^|/)\.ssh/`),
	regexp.MustCompile(`(^|/)\.aws/`),
	regexp.MustCompile(`(^|/)\.npmrc$`),
	regexp.MustCompile(`(^|/)\.pypirc$`),
}

// String redacts secrets in s.
func String(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, r := range rules {
		out = applyRule(out, r)
	}
	return out
}

func applyRule(s string, r rule) string {
	if !r.re.MatchString(s) {
		return s
	}
	if r.group == 0 {
		return r.re.ReplaceAllString(s, Placeholder)
	}
	return r.re.ReplaceAllStringFunc(s, func(match string) string {
		idx := r.re.FindStringSubmatchIndex(match)
		if idx == nil || len(idx) < 2*(r.group+1) {
			return Placeholder
		}
		start := idx[2*r.group] - idx[0]
		end := idx[2*r.group+1] - idx[0]
		if start < 0 || end < 0 || start > end || end > len(match) {
			return Placeholder
		}
		return match[:start] + Placeholder + match[end:]
	})
}

// Bytes is a convenience wrapper around String for []byte data.
func Bytes(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	return []byte(String(string(b)))
}

// Value walks an arbitrary JSON-decoded value (map[string]any, []any, string,
// numbers, etc.) and redacts any string leaves. Map keys whose lowercased
// names look secret-bearing are redacted entirely.
func Value(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return String(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSecretKey(k) {
				if _, ok := val.(string); ok {
					out[k] = Placeholder
					continue
				}
				out[k] = Placeholder
				continue
			}
			out[k] = Value(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Value(val)
		}
		return out
	default:
		return v
	}
}

func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	switch lk {
	case "password", "passwd", "secret", "token", "api_key", "apikey",
		"access_key", "accesskey", "private_key", "privatekey",
		"authorization", "_authtoken", "_auth", "api-key":
		return true
	}
	return strings.Contains(lk, "password") ||
		strings.Contains(lk, "secret") ||
		strings.Contains(lk, "token") ||
		strings.Contains(lk, "api_key") ||
		strings.Contains(lk, "apikey") ||
		strings.Contains(lk, "private_key") ||
		strings.Contains(lk, "authorization")
}

// IsSensitivePath reports whether p matches any of the credential-bearing
// path patterns.
func IsSensitivePath(p string) bool {
	if p == "" {
		return false
	}
	norm := strings.ReplaceAll(p, "\\", "/")
	for _, re := range sensitivePathREs {
		if re.MatchString(norm) {
			return true
		}
	}
	return false
}
