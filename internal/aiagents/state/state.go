package state

import "time"

// SchemaVersion is the wire/disk version of the cache file. Bump only
// on a breaking shape change; older daemons keep parsing v1.
const SchemaVersion = 1

// Source values record where the cache write came from. Diagnostic
// only — the hot path never branches on Source.
const (
	SourcePoll      = "poll"
	SourceManual    = "manual"
	SourceInstall   = "install"
	SourceWebsocket = "websocket" // reserved
)

// State is the on-disk cache shape. JSON keys are the wire format.
type State struct {
	SchemaVersion int       `json:"schema_version"`
	FetchedAt     time.Time `json:"fetched_at"`
	Source        string    `json:"source,omitempty"`
	Hooks         Hooks     `json:"hooks"`
}

// Hooks carries the feature toggles the hot path reads. Today there's
// only Enabled; per-agent granularity goes here when the contract
// grows.
type Hooks struct {
	Enabled bool `json:"enabled"`
}

// Default is the in-memory fallback for any read failure. Enabled is
// true: the hot path only runs because settings carry a DMG entry, so
// defaulting to disabled would silently turn off first-run after
// install (before the reconciler has had a chance to write the cache).
func Default() State {
	return State{SchemaVersion: SchemaVersion, Hooks: Hooks{Enabled: true}}
}
