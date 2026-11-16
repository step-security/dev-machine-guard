//go:build !windows

package device

import "testing"

// stubWindowsFirmware is a no-op off Windows: there is no firmware registry
// to blank, the CIM fixtures already decide the answer.
func stubWindowsFirmware(t *testing.T) { t.Helper() }
