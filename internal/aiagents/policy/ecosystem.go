package policy

// Ecosystem names a language family the runtime can enforce policy on.
// One ecosystem subsumes multiple package-manager binaries (e.g. npm,
// pnpm, yarn, and bun all live under EcosystemNPM). Future entries:
// pypi, cargo, go.
type Ecosystem string

const (
	EcosystemNPM Ecosystem = "npm"
)

// EcosystemFor maps an observed PM binary to its ecosystem. It returns ""
// when the binary does not belong to any ecosystem the runtime enforces
// today; callers treat that as "not policy-relevant" and fall through to
// allow.
//
// This is the single binary→ecosystem dispatch in the codebase; do not
// reproduce the table elsewhere.
func EcosystemFor(binary string) Ecosystem {
	switch binary {
	case "npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx":
		return EcosystemNPM
	}
	return ""
}

// KnownEcosystems lists the ecosystems the runtime recognizes.
func KnownEcosystems() []Ecosystem {
	return []Ecosystem{EcosystemNPM}
}

// IsKnown reports whether e is one of the ecosystems the runtime
// recognizes.
func IsKnown(e Ecosystem) bool {
	for _, k := range KnownEcosystems() {
		if k == e {
			return true
		}
	}
	return false
}
