// Package devicepolicy implements the dev-machine-guard agent side of Developer MDM
// on-device policy enforcement (PRD: "Dev Machine Guard Agent: IDE Extension
// Enforcement"). It is a thin agent: each scheduled cycle it fetches the
// backend-compiled policy and converges the `extensions.allowed` key in the
// user-scope VS Code settings.json to it (format-preserving single-key JSONC
// merge), reads it back to verify, and reports a compliance state. VS Code
// itself performs the disabling — the agent never uninstalls extensions,
// never installs anything, and never touches non-VS-Code IDEs.
//
// This subsystem shares NO code or state with the AI-agent hook-policy feature
// in internal/aiagents (PRD N11). The backend computes the compiled
// extensions.allowed object and a content hash; the agent applies it verbatim
// (compacted for canonical comparison) and never re-implements allow/deny
// merging, so on-device and exported enforcement stay at parity.
//
// Scope: Windows, macOS, and Linux, all through the same settings.json writer
// — only the per-OS path differs (%APPDATA%\Code\User, ~/Library/Application
// Support/Code/User, ~/.config/Code/User). Devices whose VS Code is already
// governed by a real MDM/admin policy at the OS policy location (HKLM/HKCU
// registry, /etc/vscode/policy.json, macOS managed preferences) are detected
// by a read-only probe and reported mdm_managed — such a policy outranks user
// settings inside VS Code, so the agent yields rather than writing a value
// that would be ignored.
//
// Seams (highest first), each independently testable:
//   - Verify (verify.go): pure {write_ok, readback_match} → state.
//   - Writer (settings_writer.go): injected; manages only the
//     extensions.allowed key, preserving the rest of the user's settings.
//   - Probe (probe.go + per-OS files): read-only managed-policy presence.
//   - Fetcher / Reporter (api.go): the two dedicated endpoints on the
//     existing developer-mdm-agent auth channel.
//   - Reconciler (reconcile.go): orchestrates fetch → probe → idempotency →
//     drift → ownership-safe write → verify → report, with malformed-→-no-op.
package devicepolicy
