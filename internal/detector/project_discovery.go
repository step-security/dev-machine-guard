package detector

import (
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Keep prior references under unreadable subtrees without claiming a fresh scan.
// Readable siblings remain eligible for real removal reconciliation.
func retainUnobservedProjects(discovered []string, known map[string]time.Time, unobserved []string) []string {
	seen := make(map[string]bool, len(discovered))
	for _, path := range discovered {
		seen[path] = true
	}
	var retained []string
	for path := range known {
		if seen[path] {
			continue
		}
		for _, root := range unobserved {
			rel, err := filepath.Rel(root, path)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				retained = append(retained, path)
				break
			}
		}
	}
	slices.Sort(retained)
	return append(discovered, retained...)
}
