//go:build !darwin && !linux && !windows

package bgpriority

// apply is a no-op on platforms without a supported priority mechanism;
// Apply logs nothing (empty desc, nil error).
func apply() (string, error) {
	return "", nil
}
