//go:build windows

package selfupdate

import "fmt"

// Windows must commit the pair through updateinstall.ReplacePair.
func swapBinary(_, _ string) error { return fmt.Errorf("single-image Windows replacement is disabled") }
