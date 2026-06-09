// Package rules implements the malicious-file detection engine for the
// enterprise agent. It evaluates backend-authored, purely declarative
// detection rules against the directories the agent already walks and reports
// matches on the existing telemetry payload as the additive `rule_scan` field.
//
// Trust & privacy model:
//
//   - Rules are pure DATA, never code. No rule field can carry a command,
//     script, executable path, or URL. A condition can only ask "does this
//     path exist, and does its content match this regex / its hash equal this
//     SHA-256?" — so a compromised backend can at worst cause a false finding
//     or a yes/no probe, never code execution or content exfiltration.
//   - A condition only ever yields a boolean. File content is never read out,
//     captured, logged, or sent — only the path, matched glob, whole-file
//     SHA-256, the per-group/per-condition booleans, and Stat-only metadata.
//   - Evaluation is hard-bounded: a per-file size guard, a global file cap, a
//     per-rule match cap, and an overall time budget (see Caps).
//
// There is NO embedded rule pack: rules live only in the backend and are
// fetched at run start. On any fetch/parse/validation failure the engine
// simply scans nothing this run — it never fails the run and never falls back
// to a local pack.
//
// The engine is drivable with zero backend and zero network: hardcode a
// RuleSet, point Scan at a temp dir of fixtures, and assert on the returned
// model.RuleScan. Prepare() is likewise pure.
package rules
