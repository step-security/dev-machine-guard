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
	"strings"

	"github.com/step-security/dev-machine-guard/internal/config"
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
// The returned Config is always populated for diagnostics — callers
// should NOT use its values when ok is false.
func Snapshot() (Config, bool) {
	c := Config{
		CustomerID:  strings.TrimSpace(config.CustomerID),
		APIEndpoint: strings.TrimSpace(config.APIEndpoint),
		APIKey:      strings.TrimSpace(config.APIKey),
	}
	if !valid(c.CustomerID) || !valid(c.APIEndpoint) || !valid(c.APIKey) {
		return c, false
	}
	return c, true
}

func valid(v string) bool {
	return v != "" && !strings.Contains(v, "{{")
}
