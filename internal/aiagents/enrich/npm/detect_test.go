package npm

import "testing"

func TestDetect(t *testing.T) {
	cases := []struct {
		cmd  string
		want Manager
		kind string
	}{
		{"npm install lodash", NPM, "install"},
		{"npm i", NPM, "install"},
		{"npm add lodash", NPM, "install"},
		{"npm ci", NPM, "install"},
		{"npm uninstall lodash", NPM, "uninstall"},
		{"npm remove lodash", NPM, "uninstall"},
		{"npm rm lodash", NPM, "uninstall"},
		{"npm un lodash", NPM, "uninstall"},
		{"npm publish", NPM, "publish"},
		{"npm audit", NPM, "audit"},
		{"npx -y create-vite my-app", NPX, "exec"},
		{"pnpm install", PNPM, "install"},
		{"pnpm i", PNPM, "install"},
		{"pnpm ci", PNPM, "install"},
		{"pnpm add react", PNPM, "install"},
		{"pnpm remove react", PNPM, "uninstall"},
		{"pnpm rm react", PNPM, "uninstall"},
		{"pnpm uninstall react", PNPM, "uninstall"},
		{"pnpm un react", PNPM, "uninstall"},
		{"pnpm", PNPM, "install"},
		{"yarn install", Yarn, "install"},
		{"yarn add lodash", Yarn, "install"},
		{"yarn remove lodash", Yarn, "uninstall"},
		{"yarn", Yarn, "install"},
		{"bun install", Bun, "install"},
		{"bun i", Bun, "install"},
		{"bun add zod", Bun, "install"},
		{"bun remove zod", Bun, "uninstall"},
		{"bun rm zod", Bun, "uninstall"},
		{"bun uninstall zod", Bun, "uninstall"},
		{"bun un zod", Bun, "uninstall"},
		{"bunx prisma generate", Bun, "exec"},
		{"/usr/local/bin/npm install", NPM, "install"},
		{"FOO=bar npm install lodash", NPM, "install"},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			d := Detect(tc.cmd)
			if d == nil {
				t.Fatalf("expected detection for %q", tc.cmd)
			}
			if d.Manager != tc.want {
				t.Fatalf("manager: got %s want %s", d.Manager, tc.want)
			}
			if d.CommandKind != tc.kind {
				t.Fatalf("kind: got %s want %s", d.CommandKind, tc.kind)
			}
		})
	}
}

func TestDetectIgnoresUnrelatedCommands(t *testing.T) {
	for _, cmd := range []string{"git push", "cargo build", "ls", "echo hi", ""} {
		if d := Detect(cmd); d != nil {
			t.Errorf("expected nil for %q, got %+v", cmd, d)
		}
	}
}

func TestConfidenceLabels(t *testing.T) {
	if got := confidence(NPM); got != "high" {
		t.Errorf("npm confidence: %s", got)
	}
	if got := confidence(Bun); got != "low" {
		t.Errorf("bun confidence: %s", got)
	}
}
