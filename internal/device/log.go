package device

import "github.com/step-security/dev-machine-guard/internal/progress"

// logger carries the package's diagnostics (stale cached ids, inherited
// markers, deferred visits). main injects the run's logger; until then, and
// in tests, nothing is printed.
var logger = progress.NewNoop()

// SetLogger routes the package's diagnostics to l.
func SetLogger(l *progress.Logger) {
	if l != nil {
		logger = l
	}
}
