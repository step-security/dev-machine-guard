//go:build windows

package configaudit

// pipStatOwner is a no-op on Windows: SID-to-username resolution is
// non-trivial and not actionable for v1 of this audit. The detector
// handles ok=false by leaving owner fields empty.
func pipStatOwner(_ string) pipOwnerInfo {
	return pipOwnerInfo{}
}
