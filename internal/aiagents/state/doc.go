// Package state owns the server-driven hook enable/disable cache.
//
// Flow:
//
//	scheduled tick / install  ──▶  Reconciler.Reconcile
//	                                   │
//	                                   ├─ Fetcher.Fetch  (GET /developer-mdm-agent/features)
//	                                   ├─ cache.Write    (~/.stepsecurity/hooks-state.json)
//	                                   └─ InstallFn / UninstallFn  (idempotent)
//
//	_hook hot path  ──▶  cache.Read  ──▶  short-circuit to allow if disabled
//
// The cache file is the single source of truth for the hot path. Both
// the polling reconciler (this package) and any future WebSocket
// transport are expected to converge on the same file, so the hot path
// never has to know which transport is active.
//
// Defaults: cache missing or unparseable ⇒ Default() (enabled). Hot path
// is fail-open by contract; a corrupt cache must not break the agent.
package state
