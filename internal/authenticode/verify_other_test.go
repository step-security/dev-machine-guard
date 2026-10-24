//go:build !windows

package authenticode

import (
	"errors"
	"testing"
)

func TestVerifyUnsupportedOffWindows(t *testing.T) {
	if _, err := Verify("/bin/sh"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Verify = %v, want ErrUnsupported", err)
	}
	if err := SamePublisher("/bin/sh", "/bin/sh"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("SamePublisher = %v, want ErrUnsupported", err)
	}
}
