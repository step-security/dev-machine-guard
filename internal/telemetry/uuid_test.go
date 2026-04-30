package telemetry

import (
	"regexp"
	"testing"
)

var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewExecutionID_FormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id, err := newExecutionID()
		if err != nil {
			t.Fatalf("newExecutionID returned error: %v", err)
		}
		if !uuidRegex.MatchString(id) {
			t.Fatalf("generated id %q does not match UUID v4 pattern", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id generated: %q", id)
		}
		seen[id] = true
	}
}
