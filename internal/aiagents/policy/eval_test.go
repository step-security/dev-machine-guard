package policy

import "testing"

func basePolicy() Policy {
	return Policy{
		Version: 1,
		Ecosystems: map[Ecosystem]EcosystemPolicy{
			EcosystemNPM: {
				Enabled:  true,
				Registry: RegistryPolicy{Allowlist: []string{"https://registry.npmjs.org/"}},
			},
		},
	}
}

func TestEvalDisabledPolicyAllows(t *testing.T) {
	p := basePolicy()
	npm := p.Ecosystems[EcosystemNPM]
	npm.Enabled = false
	p.Ecosystems[EcosystemNPM] = npm
	got := Eval(p, Request{Ecosystem: EcosystemNPM, PackageManager: "npm", CommandKind: "install", Registry: "https://evil.example/"})
	if !got.Allow {
		t.Errorf("expected allow when policy disabled")
	}
	if got.Code != CodePolicyDisabled {
		t.Errorf("code: %s", got.Code)
	}
}

func TestEvalUnknownEcosystemAllows(t *testing.T) {
	got := Eval(basePolicy(), Request{Ecosystem: Ecosystem("pypi"), PackageManager: "pip", CommandKind: "install"})
	if !got.Allow {
		t.Errorf("expected allow for ecosystem with no policy block")
	}
	if got.Code != CodePolicyDisabled {
		t.Errorf("code: %s", got.Code)
	}
}

func TestEvalAllowsAllowlistedRegistry(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://registry.npmjs.org/",
	})
	if !got.Allow {
		t.Errorf("expected allow, got: %+v", got)
	}
}

func TestEvalNormalizesTrailingSlash(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://registry.npmjs.org",
	})
	if !got.Allow {
		t.Errorf("expected allow on trailing-slash mismatch, got: %+v", got)
	}
}

func TestEvalBlocksUnallowlistedRegistry(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://evil.example/",
	})
	if got.Allow {
		t.Errorf("expected block")
	}
	if got.Code != CodeRegistryNotAllowed {
		t.Errorf("code: %s", got.Code)
	}
	if got.UserMessage != GenericBlockMessage {
		t.Errorf("user message leaked detail: %q", got.UserMessage)
	}
	if got.InternalDetail == "" {
		t.Error("expected internal detail for audit")
	}
}

func TestEvalAllowlistedFlagWinsOverNonallowlistedEffective(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://stale.example/",
		RegistryFlag:      "https://registry.npmjs.org/",
	})
	if !got.Allow {
		t.Errorf("expected allow when flag is allowlisted, got: %+v", got)
	}
}

func TestEvalBlocksRegistryFlagOverride(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://registry.npmjs.org/",
		RegistryFlag:      "https://evil.example/",
	})
	if got.Allow || got.Code != CodeRegistryFlag {
		t.Errorf("expected registry_flag block, got: %+v", got)
	}
}

func TestEvalBlocksUserconfigOverride(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://registry.npmjs.org/",
		UserconfigFlag:    "/tmp/evil.npmrc",
	})
	if got.Allow || got.Code != CodeUserconfigFlag {
		t.Errorf("expected userconfig block, got: %+v", got)
	}
}

func TestEvalBlocksEnvRegistryOverride(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://registry.npmjs.org/",
		InlineEnv:         map[string]string{"NPM_CONFIG_REGISTRY": "https://evil.example/"},
	})
	if got.Allow || got.Code != CodeRegistryEnv {
		t.Errorf("expected env block, got: %+v", got)
	}
}

func TestEvalBlocksConfigSetOnManagedRegistry(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:        EcosystemNPM,
		PackageManager:   "npm",
		CommandKind:      "config_set",
		ConfigKeyMutated: "registry",
		ConfigValue:      "https://evil.example/",
	})
	if got.Allow || got.Code != CodeRegistryNotAllowed {
		t.Errorf("expected block on config set registry to non-allowlisted, got: %+v", got)
	}
}

func TestEvalAllowsConfigSetOnUnmanagedKey(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:        EcosystemNPM,
		PackageManager:   "npm",
		CommandKind:      "config_set",
		ConfigKeyMutated: "color",
		ConfigValue:      "true",
	})
	if !got.Allow {
		t.Errorf("expected allow on unmanaged key, got: %+v", got)
	}
}

func TestEvalBlocksConfigDeleteOnManagedKey(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:        EcosystemNPM,
		PackageManager:   "npm",
		CommandKind:      "config_delete",
		ConfigKeyMutated: "registry",
	})
	if got.Allow || got.Code != CodeManagedKeyMutation {
		t.Errorf("expected block, got: %+v", got)
	}
}

func TestEvalBlocksConfigEdit(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:      EcosystemNPM,
		PackageManager: "npm",
		CommandKind:    "config_edit",
	})
	if got.Allow || got.Code != CodeManagedKeyEdit {
		t.Errorf("expected config_edit block, got: %+v", got)
	}
}

func TestEvalAllowsInsufficientData(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:      EcosystemNPM,
		PackageManager: "pnpm",
		CommandKind:    "install",
	})
	if !got.Allow {
		t.Errorf("expected allow on missing registry data")
	}
	if got.Code != CodeInsufficientData {
		t.Errorf("code: %s", got.Code)
	}
}

func TestEvalBlocksConfigSetOnManagedCooldownKey(t *testing.T) {
	got := Eval(basePolicy(), Request{
		Ecosystem:        EcosystemNPM,
		PackageManager:   "npm",
		CommandKind:      "config_set",
		ConfigKeyMutated: "min-release-age",
		ConfigValue:      "0",
	})
	if got.Allow || got.Code != CodeManagedKeyMutation {
		t.Errorf("expected block on cooldown key mutation, got: %+v", got)
	}
}

func TestEvalAllowlistPrefixMatch(t *testing.T) {
	p := basePolicy()
	npm := p.Ecosystems[EcosystemNPM]
	npm.Registry.Allowlist = []string{"https://proxy.example/orgs/acme/"}
	p.Ecosystems[EcosystemNPM] = npm
	got := Eval(p, Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://proxy.example/orgs/acme/repo-a/",
	})
	if !got.Allow {
		t.Errorf("expected prefix-match allow, got: %+v", got)
	}
	got = Eval(p, Request{
		Ecosystem:         EcosystemNPM,
		PackageManager:    "npm",
		CommandKind:       "install",
		Registry: "https://proxy.example/orgs/other/",
	})
	if got.Allow {
		t.Errorf("expected prefix-match block")
	}
}
