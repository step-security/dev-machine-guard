// Package state owns the server-driven hook enable/disable pull path.
//
// Flow:
//
//	scheduled tick  ──▶  Reconciler.Reconcile
//	                        │
//	                        ├─ Fetcher.Fetch  (GET /developer-mdm-agent/features)
//	                        └─ InstallFn / UninstallFn  (idempotent)
//
// The presence of the managed hook entry in the agent's settings file
// (~/.claude/settings.json, ~/.codex/config.toml) is the single source
// of truth. The hot path runs iff the entry is present; there is no
// separate on-disk enable flag for it to consult.
package state
