// Package secrets implements a self-contained transcript secret scanner.
// It is intentionally small: detection runs in-process with no external
// scanner binary.
package secrets

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// rule is one detection rule. Group selects which submatch to fingerprint;
// 0 means the entire match.
type rule struct {
	ID         string
	RE         *regexp.Regexp
	Group      int
	Confidence string
}

var rules = []rule{
	{
		ID:         "private_key_block",
		RE:         regexp.MustCompile(`(?s)-----BEGIN[ A-Z]*PRIVATE KEY-----.*?-----END[ A-Z]*PRIVATE KEY-----`),
		Confidence: "high",
	},
	{
		ID:         "aws_access_key_id",
		RE:         regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b`),
		Confidence: "high",
	},
	{
		ID:         "aws_secret_access_key",
		RE:         regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*"?([A-Za-z0-9/+=]{30,})`),
		Group:      1,
		Confidence: "medium",
	},
	{
		ID:         "github_token",
		RE:         regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}\b`),
		Confidence: "high",
	},
	{
		ID:         "slack_token",
		RE:         regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`),
		Confidence: "high",
	},
	{
		ID:         "bearer_token",
		RE:         regexp.MustCompile(`(?i)authorization\s*[:=]\s*"?\s*bearer\s+([A-Za-z0-9._\-+/=]{16,})`),
		Group:      1,
		Confidence: "medium",
	},
	{
		ID:         "npm_auth_token",
		RE:         regexp.MustCompile(`(?i)_authToken\s*=\s*([^\s"]+)`),
		Group:      1,
		Confidence: "high",
	},
	{
		ID:         "generic_api_key",
		RE:         regexp.MustCompile(`(?i)\b(?:api[_-]?key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})`),
		Group:      1,
		Confidence: "low",
	},
}

// fingerprint returns a stable hash for a secret value, suitable for
// dedup/correlation without storing the value itself.
func fingerprint(secret string) string {
	h := sha256.Sum256([]byte(secret))
	// 12 bytes / 24 hex chars is plenty for de-duplication.
	return hex.EncodeToString(h[:12])
}

// mask collapses the middle of a secret so previews carry no usable bytes.
func mask(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:2] + strings.Repeat("*", len(secret)-4) + secret[len(secret)-2:]
}
