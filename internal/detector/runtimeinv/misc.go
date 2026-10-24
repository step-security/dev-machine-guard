package runtimeinv

import (
	"os"
	"regexp"
	"strings"
)

// snapRe matches a snap mount: /snap, or /var/lib/snapd/snap where /snap is
// a symlink to it (Fedora, Arch).
var snapRe = regexp.MustCompile(`^(?:/var/lib/snapd)?/snap/([^/]+)/`)

// isScript reports a file starting with a shebang.
func isScript(path string) bool {
	// #nosec G304 -- path is a binary found by the runtime walk; only its first two bytes are read.
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 2)
	n, _ := f.Read(b)
	return n == 2 && string(b) == "#!"
}

// snapBundler names the snap that privately ships a runtime: one under
// /snap/<name>/ where <name> is not that runtime's own snap (core18's
// python3 vs the node snap's node).
func snapBundler(runtime, real string) string {
	m := snapRe.FindStringSubmatch(real)
	if m == nil {
		return ""
	}
	name := m[1]
	if strings.HasPrefix(name, runtime) {
		return ""
	}
	return name
}
