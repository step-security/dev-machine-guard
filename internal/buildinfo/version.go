package buildinfo

import "fmt"

const (
	Version  = "1.9.1"
	AgentURL = "https://github.com/step-security/dev-machine-guard"
)

// Build-time variables set via -ldflags by goreleaser or Makefile.
var (
	GitCommit     string // short commit hash (Makefile) or full commit (goreleaser)
	ReleaseTag    string // e.g., "v1.9.1" (goreleaser only)
	ReleaseBranch string // e.g., "main" (goreleaser only)
)

// VersionString returns the display version, including the git commit if available.
func VersionString() string {
	if GitCommit != "" {
		short := GitCommit
		if len(short) > 7 {
			short = short[:7]
		}
		return fmt.Sprintf("%s (%s)", Version, short)
	}
	return Version
}
