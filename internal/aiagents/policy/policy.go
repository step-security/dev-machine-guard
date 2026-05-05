// Package policy holds the policy data model and pure decision
// evaluator. The package is agent-agnostic: adapters consume only the
// resulting Decision; the package never imports adapter code.
//
// The active policy is the embedded default at policy/builtin/policy.json.
// A future revision will replace Builtin() with a fetch from the
// StepSecurity backend; call sites consume Policy values and need not
// change. There is intentionally no on-disk override.
package policy

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

// Mode controls what the runtime does with a policy violation.
//
//   - ModeAudit: evaluate, persist a finding describing what *would* have
//     blocked, but always emit an allow response to the agent.
//   - ModeBlock: evaluate, persist the finding, and on an explicit
//     violation flip the response to block.
//
// Mode is policy-wide; there is no per-ecosystem override. Endpoint-level
// behavior is the call the org wants to make uniformly across ecosystems.
type Mode string

const (
	ModeAudit Mode = "audit"
	ModeBlock Mode = "block"
)

// Policy is the active policy document. Per-ecosystem enforcement lives
// under Ecosystems; a missing or disabled block means the runtime allows
// that ecosystem unconditionally and emits no policy_decision.
type Policy struct {
	Version    int                           `json:"version"`
	Mode       Mode                          `json:"mode,omitempty"`
	Ecosystems map[Ecosystem]EcosystemPolicy `json:"ecosystems"`
}

// ResolveMode returns p.Mode if it is a known value; otherwise ModeAudit.
// Unknown or empty strings collapse to audit so a malformed policy can
// never silently switch the endpoint into block mode.
func ResolveMode(p Policy) Mode {
	switch p.Mode {
	case ModeBlock:
		return ModeBlock
	default:
		return ModeAudit
	}
}

// EcosystemPolicy carries the per-ecosystem enforcement settings. Today
// every ecosystem is registry-pin only; future fields land here without
// changing the surrounding shape.
type EcosystemPolicy struct {
	Enabled  bool           `json:"enabled"`
	Registry RegistryPolicy `json:"registry"`
}

// RegistryPolicy expresses the secure-registry pinning policy.
type RegistryPolicy struct {
	// Allowlist is the set of permitted registry URLs. Matching is
	// prefix-based after trailing-slash normalization.
	Allowlist []string `json:"allowlist"`
}

//go:embed builtin/policy.json
var builtinPolicyJSON []byte

// Builtin returns the embedded policy. The embedded JSON is checked at
// build time by the test suite; a parse failure here is a programmer
// error, not a runtime condition.
func Builtin() Policy {
	var p Policy
	if err := json.Unmarshal(builtinPolicyJSON, &p); err != nil {
		panic(fmt.Errorf("policy: builtin parse: %w", err))
	}
	return p
}
