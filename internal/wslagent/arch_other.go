//go:build !windows

package wslagent

import "runtime"

// nativeArch outside Windows: only the Windows agent launches WSL guests, so
// the build arch is enough here.
func nativeArch() string { return runtime.GOARCH }
