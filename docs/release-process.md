# StepSecurity Dev Machine Guard — Release Process

This document describes how releases are created, signed, notarized, and verified.

> Back to [README](../README.md) | See also: [CHANGELOG](../CHANGELOG.md) | [Versioning](../VERSIONING.md)

---

## Overview

Releases are a two-phase process:

1. **CI (automated)** — GitHub Actions builds the universal macOS binary, signs it with Sigstore, and creates a **draft** release with the binary named `stepsecurity-dev-machine-guard-VERSION-darwin_unnotarized`.
2. **Apple notarization (manual)** — Download the binary, sign and notarize it with an Apple Developer account, upload the notarized binary to the draft release, and publish.

---

## How to Create a Release

### 1. Bump the version

Update `Version` in `internal/buildinfo/version.go`:

```go
const Version = "1.9.1"
```

Update [CHANGELOG.md](../CHANGELOG.md). Commit and push to `main`.

### 2. Trigger the release workflow

1. Go to [Actions > Release](https://github.com/step-security/dev-machine-guard/actions/workflows/release.yml)
2. Click **Run workflow** on the `main` branch

The workflow will:
- Create a git tag (`v1.9.1`)
- Build a universal macOS binary (amd64 + arm64) via GoReleaser
- Sign with Sigstore cosign (keyless)
- Upload as `stepsecurity-dev-machine-guard-VERSION-darwin_unnotarized` to a **draft** release
- Record the SHA256 of the unnotarized binary in the release notes
- Generate SLSA build provenance attestation

### 3. Apple notarization (manual)

On a Mac with the Apple Developer certificate installed:

```bash
VERSION="1.9.1"

# Download the unnotarized binary
gh release download "v${VERSION}" --repo step-security/dev-machine-guard \
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-darwin_unnotarized"

# Rename for signing
cp "stepsecurity-dev-machine-guard-${VERSION}-darwin_unnotarized" \
   "stepsecurity-dev-machine-guard-${VERSION}-darwin"

# Sign with Apple Developer ID
codesign --sign "Developer ID Application: <COMPANY> (<TEAM_ID>)" \
  --options runtime --timestamp "stepsecurity-dev-machine-guard-${VERSION}-darwin"

# Notarize with Apple (~5 min)
xcrun notarytool submit "stepsecurity-dev-machine-guard-${VERSION}-darwin" \
  --apple-id <APPLE_ID_EMAIL> --team-id <TEAM_ID> \
  --password <APP_SPECIFIC_PASSWORD> --wait

# Upload the notarized binary to the draft release
gh release upload "v${VERSION}" "stepsecurity-dev-machine-guard-${VERSION}-darwin" \
  --repo step-security/dev-machine-guard
```

### 4. Publish the release

```bash
gh release edit "v${VERSION}" --repo step-security/dev-machine-guard \
  --draft=false --latest
```

---

## Release Artifacts

Each release includes:

| Artifact | Description |
|----------|-------------|
| `stepsecurity-dev-machine-guard-VERSION-darwin` | Notarized universal macOS binary (amd64 + arm64) |
| `stepsecurity-dev-machine-guard-VERSION-darwin_unnotarized` | Original CI-built binary (for provenance verification) |
| `stepsecurity-dev-machine-guard-VERSION-darwin_unnotarized.bundle` | Sigstore cosign bundle for the unnotarized binary |
| `stepsecurity-dev-machine-guard.sh` | Legacy shell script |
| `stepsecurity-dev-machine-guard.sh.bundle` | Sigstore cosign bundle for the shell script |

---

## Verifying a Release

### Verify a release

```bash
VERSION="1.9.1"

# Download release artifacts
gh release download "v${VERSION}" --repo step-security/dev-machine-guard \
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-darwin*"

# Verify Apple signature and notarization
codesign --verify --deep --strict "stepsecurity-dev-machine-guard-${VERSION}-darwin"
spctl --assess --type execute "stepsecurity-dev-machine-guard-${VERSION}-darwin"

# Verify Sigstore signature on the unnotarized binary
cosign verify-blob "stepsecurity-dev-machine-guard-${VERSION}-darwin_unnotarized" \
  --bundle "stepsecurity-dev-machine-guard-${VERSION}-darwin_unnotarized.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "github.com/.*/dev-machine-guard"

# Verify build provenance
gh attestation verify "stepsecurity-dev-machine-guard-${VERSION}-darwin_unnotarized" \
  --repo step-security/dev-machine-guard
```

---

## Immutability Guarantees

1. **Draft → publish flow** — binaries are uploaded to a draft release, notarized manually, then published. Once published, the release is immutable.
2. **Sigstore transparency log** — the unnotarized binary signature is recorded in the public [Rekor](https://rekor.sigstore.dev/) transparency log.
3. **SLSA build provenance** — attestation links the artifact to the exact workflow run, commit SHA, and build environment.
4. **Duplicate tag check** — the release workflow fails if the tag already exists.

---

## Further Reading

- [CHANGELOG.md](../CHANGELOG.md) — release history
- [VERSIONING.md](../VERSIONING.md) — versioning scheme
- [Sigstore documentation](https://docs.sigstore.dev/) — how keyless signing works
- [SLSA](https://slsa.dev/) — supply chain integrity framework
