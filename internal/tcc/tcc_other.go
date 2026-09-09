//go:build !darwin

package tcc

func buildProtectedPaths(_ string) map[string]struct{} {
	return nil
}

func protectedPrefixes() []string {
	return nil
}

// networkVolumeMounts is darwin-only: the Network Volumes TCC service does
// not exist elsewhere, so there is nothing to skip.
func networkVolumeMounts() []string {
	return nil
}
