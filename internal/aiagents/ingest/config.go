// Package ingest owns the AI-agent telemetry upload path: the stricter
// enterprise-config gate (this file) and the HTTP client that POSTs
// events to /v1/{customer_id}/ai-agents/events.
//
// The stricter gate exists because DMG's `config.IsEnterpriseMode()`
// checks only APIKey — that's the right call for the scan/telemetry
// paths, but it's too lax for the hook upload path. A missing CustomerID
// or APIEndpoint here would silently misroute uploads, so we require all
// three credentials to be present and not bearing build-time
// `{{...}}` placeholders.
package ingest

import (
	"os"
	"strings"

	"github.com/step-security/dev-machine-guard/internal/config"
)

// Env-var overrides let a developer redirect uploads at hook-invocation
// time without rewriting the on-disk config (which an MDM agent may
// clobber on its enforcement tick). When set and non-empty, each var
// wins over both the config file and any build-time bake.
const (
	envCustomerID  = "DMG_CUSTOMER_ID"
	envAPIEndpoint = "DMG_API_ENDPOINT"
	envAPIKey      = "DMG_API_KEY"
)

// Config is a snapshot of the three credentials required to upload
// AI-agent events. All fields are TrimSpace'd at read time.
type Config struct {
	CustomerID  string
	APIEndpoint string
	APIKey      string
}

// Snapshot reads the current process-wide DMG config (populated by an
// earlier call to config.Load) and returns it alongside an "enterprise
// ready" bool. The bool is true iff every field is non-empty after
// trimming AND none contain the build-time placeholder marker `{{`.
//
// Env-var overrides (DMG_CUSTOMER_ID, DMG_API_ENDPOINT, DMG_API_KEY)
// take precedence over the config file when set and non-empty. They
// exist for local dev where an MDM agent may revert the on-disk file.
//
// The returned Config is always populated for diagnostics — callers
// should NOT use its values when ok is false.
func Snapshot() (Config, bool) {
	c := Config{
		CustomerID:  pick(envCustomerID, config.CustomerID),
		APIEndpoint: pick(envAPIEndpoint, config.APIEndpoint),
		APIKey:      pick(envAPIKey, config.APIKey),
	}
	if !valid(c.CustomerID) || !valid(c.APIEndpoint) || !valid(c.APIKey) {
		return c, false
	}
	return c, true
}

// pick returns the env-var value if set and non-empty, otherwise the
// fallback (typically the config-file value). Both are trimmed.
func pick(envVar, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(envVar)); v != "" {
		return v
	}
	return strings.TrimSpace(fallback)
}

func valid(v string) bool {
	return v != "" && !strings.Contains(v, "{{")
}
