//go:build !darwin

package tcc

func buildProtectedPaths(_ string) map[string]struct{} {
	return nil
}

func protectedPrefixes() []string {
	return nil
}
