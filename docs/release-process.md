# StepSecurity Dev Machine Guard — Release Process

This document describes how releases are created, signed, notarized, and verified.

> Back to [README](../README.md) | See also: [CHANGELOG](../CHANGELOG.md) | [Versioning](../VERSIONING.md)

---

## Overview

Releases are a two-phase process:

1. **CI (automated)** — GitHub Actions builds the universal macOS binary, Windows binaries (amd64 + arm64), and Linux binaries (amd64 + arm64), signs them all with Sigstore, and creates a **draft** release.
2. **Apple notarization (manual)** — Download the macOS binary, sign and notarize it with an Apple Developer account, upload the notarized binary to the draft release, and publish.

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
- Build via GoReleaser:
  - Universal macOS binary (amd64 + arm64)
  - Windows binaries (amd64 + arm64)
  - Linux binaries (amd64 + arm64)
- Sign all artifacts with Sigstore cosign (keyless)
- Upload to a **draft** release
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
| `stepsecurity-dev-machine-guard-darwin_unnotarized.bundle` | Sigstore cosign bundle for the unnotarized binary |
| `stepsecurity-dev-machine-guard-VERSION-windows_amd64.exe` | Windows 64-bit binary |
| `stepsecurity-dev-machine-guard-windows_amd64.exe.bundle` | Sigstore cosign bundle for the Windows amd64 binary |
| `stepsecurity-dev-machine-guard-VERSION-windows_arm64.exe` | Windows ARM64 binary |
| `stepsecurity-dev-machine-guard-windows_arm64.exe.bundle` | Sigstore cosign bundle for the Windows arm64 binary |
| `stepsecurity-dev-machine-guard-VERSION-linux_amd64` | Linux 64-bit binary |
| `stepsecurity-dev-machine-guard-linux_amd64.bundle` | Sigstore cosign bundle for the Linux amd64 binary |
| `stepsecurity-dev-machine-guard-VERSION-linux_arm64` | Linux ARM64 binary |
| `stepsecurity-dev-machine-guard-linux_arm64.bundle` | Sigstore cosign bundle for the Linux arm64 binary |
| `stepsecurity-dev-machine-guard-VERSION-amd64.deb` | Debian/Ubuntu amd64 package |
| `stepsecurity-dev-machine-guard-VERSION-amd64.deb.bundle` | Sigstore cosign bundle for the Debian amd64 package |
| `stepsecurity-dev-machine-guard-VERSION-arm64.deb` | Debian/Ubuntu arm64 package |
| `stepsecurity-dev-machine-guard-VERSION-arm64.deb.bundle` | Sigstore cosign bundle for the Debian arm64 package |
| `stepsecurity-dev-machine-guard-VERSION-amd64.rpm` | RHEL/Fedora amd64 package |
| `stepsecurity-dev-machine-guard-VERSION-amd64.rpm.bundle` | Sigstore cosign bundle for the RPM amd64 package |
| `stepsecurity-dev-machine-guard-VERSION-arm64.rpm` | RHEL/Fedora arm64 package |
| `stepsecurity-dev-machine-guard-VERSION-arm64.rpm.bundle` | Sigstore cosign bundle for the RPM arm64 package |
| `stepsecurity-dev-machine-guard.sh` | Legacy shell script |
| `stepsecurity-dev-machine-guard.sh.bundle` | Sigstore cosign bundle for the shell script |

---

## Verifying a Release

### Verify macOS release

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
  --bundle "stepsecurity-dev-machine-guard-darwin_unnotarized.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/step-security/dev-machine-guard/.github/workflows/"

# Verify build provenance
gh attestation verify "stepsecurity-dev-machine-guard-${VERSION}-darwin_unnotarized" \
  --repo step-security/dev-machine-guard
```

### Install via package manager (Linux)

**Debian / Ubuntu:**

```bash
VERSION="1.9.1"
ARCH="amd64"  # or arm64

gh release download "v${VERSION}" --repo step-security/dev-machine-guard \
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-${ARCH}.deb"

sudo dpkg -i "stepsecurity-dev-machine-guard-${VERSION}-${ARCH}.deb"
```

**RHEL / Fedora:**

```bash
VERSION="1.9.1"
ARCH="amd64"  # or arm64

gh release download "v${VERSION}" --repo step-security/dev-machine-guard \
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-${ARCH}.rpm"

sudo rpm -i "stepsecurity-dev-machine-guard-${VERSION}-${ARCH}.rpm"
```

### Verify Linux release

```bash
VERSION="1.9.1"
ARCH="amd64"  # or arm64

# Download release artifacts
gh release download "v${VERSION}" --repo step-security/dev-machine-guard \
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-linux_${ARCH}*"

# Verify Sigstore signature
cosign verify-blob "stepsecurity-dev-machine-guard-${VERSION}-linux_${ARCH}" \
  --bundle "stepsecurity-dev-machine-guard-linux_${ARCH}.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/step-security/dev-machine-guard/.github/workflows/"

# Verify build provenance
gh attestation verify "stepsecurity-dev-machine-guard-${VERSION}-linux_${ARCH}" \
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
