//go:build linux

package devicepolicy

// linuxPolicyFilePath is VS Code's managed-policy file on Linux, read by its
// FilePolicyService. World-readable when an MDM/admin creates it, so the probe
// needs no elevation.
const linuxPolicyFilePath = "/etc/vscode/policy.json"

// ProbeManagedPolicy reports whether an AllowedExtensions policy exists in the
// Linux policy file.
func ProbeManagedPolicy() (bool, string) {
	if jsonFileHasKey(linuxPolicyFilePath, allowedExtensionsName) {
		return true, linuxPolicyFilePath + " [" + allowedExtensionsName + "]"
	}
	return false, ""
}
