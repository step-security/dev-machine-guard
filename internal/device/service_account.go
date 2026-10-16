package device

import (
	"strings"

	"github.com/step-security/dev-machine-guard/internal/executor"
	"github.com/step-security/dev-machine-guard/internal/model"
)

// IsServiceAccount identifies daemon contexts for the no_user_logged_in field.
func IsServiceAccount(exec executor.Executor, user string) bool {
	return isServiceAccount(exec.GOOS(), exec.IsRoot(), user)
}

func isServiceAccount(platform string, root bool, user string) bool {
	u := strings.TrimSpace(user)
	if u == "" || u == "unknown" {
		return true
	}
	if u == "root" && root {
		return true
	}
	lower := strings.ToLower(u)
	for _, prefix := range []string{`nt authority\`, `nt service\`, `window manager\`, `font driver host\`} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if platform == model.PlatformWindows {
		switch lower {
		case "system", "local service", "network service":
			return true
		}
		if strings.HasSuffix(lower, "$") {
			return true
		}
	}
	return false
}
