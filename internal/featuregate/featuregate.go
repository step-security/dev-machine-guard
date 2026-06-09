// Package featuregate gates capabilities whose corresponding backend
// support has not yet shipped. Each Feature constant maps 1:1 to a
// product capability and stays inert until its entry is added to the
// allowlist below.
//
// Bypass for internal dogfooding: pass --override-gate on the CLI or set
// STEPSECURITY_OVERRIDE_GATE=1 in the environment. The env-var form is
// the only way to flip the gate before cli.Parse runs, which the _hook
// hot path relies on (main returns before Parse for that subcommand).
package featuregate

import (
	"fmt"
	"os"
)

type Feature string

const (
	FeatureAIAgentHooks    Feature = "ai-agent-hooks"
	FeatureNPMRCAudit      Feature = "npmrc-audit"
	FeaturePipConfigAudit  Feature = "pipconfig-audit"
	FeaturePnpmConfigAudit Feature = "pnpm-config-audit"
	FeatureBunConfigAudit  Feature = "bun-config-audit"
	FeatureYarnConfigAudit Feature = "yarn-config-audit"
)

// enabled lists features safe to ship today. Uncomment a line once its
// backend support has merged.
var enabled = map[Feature]bool{
	// FeatureAIAgentHooks:    true,
	FeatureNPMRCAudit:     true,
	FeaturePipConfigAudit: true,
	// FeaturePnpmConfigAudit: true,
	// FeatureBunConfigAudit:  true,
	// FeatureYarnConfigAudit: true,
}

var override bool

func init() {
	if v := os.Getenv("STEPSECURITY_OVERRIDE_GATE"); v == "1" || v == "true" {
		override = true
	}
}

// EnableOverride turns on the global override. main calls this when
// --override-gate is present on the command line.
func EnableOverride() { override = true }

// IsEnabled reports whether a feature should run.
func IsEnabled(f Feature) bool {
	return override || enabled[f]
}

// UnavailableMessage returns the user-facing string printed when a gated
// command is invoked. Kept here so the wording stays identical across
// every visible command site.
func UnavailableMessage(command string) string {
	return fmt.Sprintf("%s is available only in beta and not yet generally available", command)
}
