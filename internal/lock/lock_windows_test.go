//go:build windows

package lock

import (
	"fmt"
	"testing"
	"time"
)

// testLockTarget returns a per-test mutex name so tests never contend with a
// real agent run on the same machine.
func testLockTarget(t *testing.T) string {
	return fmt.Sprintf("StepSecurityDevMachineGuardTest-%d", time.Now().UnixNano())
}
