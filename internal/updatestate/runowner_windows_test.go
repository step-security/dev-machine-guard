//go:build windows

package updatestate

import (
	"strings"
	"testing"
)

func TestRunOwnerIsATokenSID(t *testing.T) {
	if o := RunOwner(); !strings.HasPrefix(o, "S-1-") || !validRunOwner(o) {
		t.Fatalf("RunOwner = %q, want a SID usable in a file name", o)
	}
}
