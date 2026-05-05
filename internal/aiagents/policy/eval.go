package policy

import (
	"strings"
)

// Request is what the runtime hands to Eval after parsing a hook payload.
// All fields are optional except Ecosystem + CommandKind; missing data
// tends toward Allow (fail-open).
type Request struct {
	Ecosystem         Ecosystem         // resolved by EcosystemFor(parsed.Binary)
	PackageManager    string            // raw binary observed: "npm" | "pnpm" | "yarn" | "bun" | "npx" | ...
	CommandKind       string            // "install" | "config_set" | "config_delete" | "config_edit" | "exec" | ...
	Registry          string            // resolved per cwd, e.g. "https://registry.npmjs.org/"
	RegistryFlag      string            // value of --registry= if present on argv
	UserconfigFlag    string            // value of --userconfig= if present on argv
	InlineEnv         map[string]string // KEY=VAL prefix env vars on argv
	ConfigKeyMutated  string            // for config_set/config_delete: which key
	ConfigValue       string            // for config_set: the new value
}

// Eval is a pure function over Policy + Request. The runtime persists the
// returned Decision both on the JSONL event and (via the adapter) on the
// stdout response.
func Eval(p Policy, req Request) Decision {
	block, ok := p.Ecosystems[req.Ecosystem]
	if !ok || !block.Enabled {
		return AllowDecision(CodePolicyDisabled, "policy disabled for ecosystem "+string(req.Ecosystem))
	}
	return evalForEcosystem(block, req)
}

func evalForEcosystem(block EcosystemPolicy, req Request) Decision {
	switch req.CommandKind {
	case "install", "publish":
		return evalInstall(block, req)
	case "config_set":
		return evalConfigSet(block, req)
	case "config_delete":
		if isManagedKey(req.Ecosystem, req.PackageManager, req.ConfigKeyMutated) {
			return BlockDecision(CodeManagedKeyMutation,
				"config delete on managed key "+req.ConfigKeyMutated)
		}
		return AllowDecision(CodeAllowed, "non-managed config delete")
	case "config_edit":
		return BlockDecision(CodeManagedKeyEdit,
			"interactive config edit could mutate managed keys")
	default:
		return AllowDecision(CodeNotInstallCommand,
			"command kind "+req.CommandKind+" not policy-relevant")
	}
}

func evalInstall(block EcosystemPolicy, req Request) Decision {
	if req.UserconfigFlag != "" {
		return BlockDecision(CodeUserconfigFlag,
			"--userconfig points at "+req.UserconfigFlag)
	}
	// Precedence: a CLI flag wins, then inline env, then system config.
	// We only check the level the package manager will actually use; the
	// lower-precedence registries are moot for this invocation.
	if req.RegistryFlag != "" {
		if !registryAllowed(block.Registry.Allowlist, req.RegistryFlag) {
			return BlockDecision(CodeRegistryFlag,
				"--registry="+req.RegistryFlag+" not in allowlist")
		}
		return AllowDecision(CodeAllowed, "registry flag allowlisted")
	}
	if envReg := envRegistryOverride(req.Ecosystem, req.InlineEnv); envReg != "" {
		if !registryAllowed(block.Registry.Allowlist, envReg) {
			return BlockDecision(CodeRegistryEnv,
				"inline env registry "+envReg+" not in allowlist")
		}
		return AllowDecision(CodeAllowed, "env registry allowlisted")
	}
	if req.Registry == "" {
		// Cannot resolve; fail-open with an audit-able code.
		return AllowDecision(CodeInsufficientData, "no registry resolved")
	}
	if !registryAllowed(block.Registry.Allowlist, req.Registry) {
		return BlockDecision(CodeRegistryNotAllowed,
			"registry "+req.Registry+" not in allowlist")
	}
	return AllowDecision(CodeAllowed, "registry allowlisted")
}

func evalConfigSet(block EcosystemPolicy, req Request) Decision {
	if !isManagedKey(req.Ecosystem, req.PackageManager, req.ConfigKeyMutated) {
		return AllowDecision(CodeAllowed, "non-managed config key")
	}
	// Setting a managed registry key to an allowlisted value is fine.
	if isRegistryKey(req.Ecosystem, req.PackageManager, req.ConfigKeyMutated) {
		if registryAllowed(block.Registry.Allowlist, req.ConfigValue) {
			return AllowDecision(CodeAllowed, "managed registry set to allowlisted value")
		}
		return BlockDecision(CodeRegistryNotAllowed,
			"config set "+req.ConfigKeyMutated+"="+req.ConfigValue+" not allowlisted")
	}
	// Cooldown / other managed keys: block unconditional mutation; the
	// authoritative value is owned by the runtime.
	return BlockDecision(CodeManagedKeyMutation,
		"config set on managed key "+req.ConfigKeyMutated)
}

// registryAllowed normalizes both sides (trailing slash) and prefix-matches.
func registryAllowed(allowlist []string, candidate string) bool {
	c := normalizeRegistry(candidate)
	if c == "" {
		return false
	}
	for _, a := range allowlist {
		n := normalizeRegistry(a)
		if n == "" {
			continue
		}
		if strings.HasPrefix(c, n) {
			return true
		}
	}
	return false
}

func normalizeRegistry(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Lowercase scheme + host comparisons are too lossy for path-bearing
	// registry URLs; we instead normalize trailing slash only. Callers
	// supply real URLs (no quoting).
	if !strings.HasSuffix(s, "/") {
		s += "/"
	}
	return s
}

// managedKeysFor returns the per-PM managed-key table for an ecosystem.
// New ecosystems add a case; non-config-set ecosystems can return nil.
func managedKeysFor(eco Ecosystem) map[string]map[string]struct{} {
	switch eco {
	case EcosystemNPM:
		return map[string]map[string]struct{}{
			"npm":  {"registry": {}, "min-release-age": {}, "ignore-scripts": {}},
			"pnpm": {"registry": {}, "minimum-release-age": {}, "min-release-age": {}, "ignoreScripts": {}, "ignore-scripts": {}},
			"yarn": {"npmRegistryServer": {}, "npmMinimalAgeGate": {}, "enableScripts": {}},
			"bun":  {"registry": {}, "minimumReleaseAge": {}, "ignoreScripts": {}},
		}
	}
	return nil
}

func isManagedKey(eco Ecosystem, pm, key string) bool {
	if key == "" {
		return false
	}
	table := managedKeysFor(eco)
	if table == nil {
		return false
	}
	if m, ok := table[pm]; ok {
		_, ok := m[key]
		return ok
	}
	return false
}

func isRegistryKey(eco Ecosystem, pm, key string) bool {
	switch eco {
	case EcosystemNPM:
		if pm == "yarn" {
			return key == "npmRegistryServer"
		}
		return key == "registry"
	}
	return false
}

// envRegistryOverride returns the registry URL set by an inline
// `KEY=VAL <pm>` prefix, or "" if none of the recognized keys are set.
func envRegistryOverride(eco Ecosystem, env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	var keys []string
	switch eco {
	case EcosystemNPM:
		keys = []string{
			"NPM_CONFIG_REGISTRY",
			"PNPM_CONFIG_REGISTRY",
			"YARN_NPM_REGISTRY_SERVER",
			"BUN_CONFIG_REGISTRY",
		}
	}
	for _, k := range keys {
		if v, ok := env[k]; ok && v != "" {
			return v
		}
	}
	return ""
}
