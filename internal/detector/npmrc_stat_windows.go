//go:build windows

package detector

// statOwner is a no-op on Windows: getting a meaningful owner string from a
// SID is non-trivial and not actionable for the audit's first cut. The
// detector handles ownerInfo.OK == false by leaving owner fields empty.
func statOwner(_ string) ownerInfo {
	return ownerInfo{}
}
