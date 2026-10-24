//go:build !windows

package selfupdate

import "runtime"

func nativeArch() string { return runtime.GOARCH }
