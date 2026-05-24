# StepSecurity Dev Machine Guard — Release Process

This document describes how releases are created, signed, notarized, and verified.

> Back to [README](../README.md) | See also: [CHANGELOG](../CHANGELOG.md) | [Versioning](../VERSIONING.md)

---

## Overview

Releases are a two-phase process:

1. **CI (automated, gated)** — GitHub Actions builds binaries for all platforms, Authenticode-signs the Windows `.exe`s and `.msi`s via Azure Trusted Signing, Sigstore-signs every artifact (after Authenticode for Windows, so cosign bundles match the bytes users download), creates a **draft** release, and emits SLSA build provenance attestations. The Windows signing job runs in the `release` GitHub Environment, which requires two reviewers and is restricted to `main`.
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
  - Windows binaries (amd64 + arm64; agent + launcher)
  - Linux binaries (amd64 + arm64)
  - Build MSIs (x64 + arm64) from the signed Windows binaries
- Authenticode-sign Windows `.exe`s and `.msi`s via Azure Trusted Signing (with RFC3161 timestamp from Microsoft)
- Sign all artifacts with Sigstore cosign (keyless); Windows cosign bundles cover the post-Authenticode bytes
- Upload to a **draft** release
- Generate SLSA build provenance attestation

**Approval gate**: the Windows signing job waits at the `release` environment — two reviewers must approve before signing runs. The job won't start until the macOS/Linux portion finishes the draft upload, so the macOS notarization step below can run in parallel with reviewers approving.

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
| `stepsecurity-dev-machine-guard-VERSION-windows_amd64.exe` | Authenticode-signed Windows 64-bit agent |
| `stepsecurity-dev-machine-guard-windows_amd64.exe.bundle` | Sigstore cosign bundle (covers the signed bytes) |
| `stepsecurity-dev-machine-guard-VERSION-windows_arm64.exe` | Authenticode-signed Windows ARM64 agent |
| `stepsecurity-dev-machine-guard-windows_arm64.exe.bundle` | Sigstore cosign bundle (covers the signed bytes) |
| `stepsecurity-dev-machine-guard-task-VERSION-windows_amd64.exe` | Authenticode-signed Windows 64-bit launcher |
| `stepsecurity-dev-machine-guard-task-windows_amd64.exe.bundle` | Sigstore cosign bundle (covers the signed bytes) |
| `stepsecurity-dev-machine-guard-task-VERSION-windows_arm64.exe` | Authenticode-signed Windows ARM64 launcher |
| `stepsecurity-dev-machine-guard-task-windows_arm64.exe.bundle` | Sigstore cosign bundle (covers the signed bytes) |
| `stepsecurity-dev-machine-guard-VERSION-x64.msi` | Authenticode-signed Windows x64 MSI installer |
| `stepsecurity-dev-machine-guard-VERSION-x64.msi.bundle` | Sigstore cosign bundle for the MSI |
| `stepsecurity-dev-machine-guard-VERSION-arm64.msi` | Authenticode-signed Windows ARM64 MSI installer |
| `stepsecurity-dev-machine-guard-VERSION-arm64.msi.bundle` | Sigstore cosign bundle for the MSI |
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

### Verify Windows release

Run on a Windows machine (or any Windows VM) with the Windows 10/11 SDK installed for `signtool`. PowerShell 5.1 is fine.

```powershell
$VERSION = "1.9.1"

gh release download "v$VERSION" --repo step-security/dev-machine-guard `
  --pattern "stepsecurity-dev-machine-guard-$VERSION-windows_amd64.exe" `
  --pattern "stepsecurity-dev-machine-guard-windows_amd64.exe.bundle" `
  --pattern "stepsecurity-dev-machine-guard-$VERSION-x64.msi" `
  --pattern "stepsecurity-dev-machine-guard-$VERSION-x64.msi.bundle"

# Authenticode + RFC3161 timestamp
Get-AuthenticodeSignature ".\stepsecurity-dev-machine-guard-$VERSION-windows_amd64.exe"
Get-AuthenticodeSignature ".\stepsecurity-dev-machine-guard-$VERSION-x64.msi"
# Expected: Status=Valid, SignerCertificate.Subject contains "Step Security, Inc.",
# TimeStamperCertificate.Subject contains "Microsoft".

# Full chain via signtool (path may vary by Windows SDK version)
$signtool = Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" |
            Sort-Object FullName -Descending | Select-Object -First 1
& $signtool.FullName verify /pa /v ".\stepsecurity-dev-machine-guard-$VERSION-windows_amd64.exe"
& $signtool.FullName verify /pa /v ".\stepsecurity-dev-machine-guard-$VERSION-x64.msi"
```

Verify the Sigstore bundle covers the Authenticode-signed bytes (run on any machine with cosign installed):

```bash
VERSION="1.9.1"

cosign verify-blob "stepsecurity-dev-machine-guard-${VERSION}-windows_amd64.exe" \
  --bundle "stepsecurity-dev-machine-guard-windows_amd64.exe.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/step-security/dev-machine-guard/.github/workflows/"

cosign verify-blob "stepsecurity-dev-machine-guard-${VERSION}-x64.msi" \
  --bundle "stepsecurity-dev-machine-guard-${VERSION}-x64.msi.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/step-security/dev-machine-guard/.github/workflows/"

# SLSA build provenance
gh attestation verify "stepsecurity-dev-machine-guard-${VERSION}-windows_amd64.exe" \
  --repo step-security/dev-machine-guard
gh attestation verify "stepsecurity-dev-machine-guard-${VERSION}-x64.msi" \
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
2. **Sigstore transparency log** — every artifact's signature is recorded in the public [Rekor](https://rekor.sigstore.dev/) transparency log. Windows cosign bundles cover the post-Authenticode bytes, so they match what users download.
3. **SLSA build provenance** — attestation links the artifact to the exact workflow run, commit SHA, and build environment.
4. **Authenticode + RFC3161 timestamp** — Windows `.exe` and `.msi` signatures from Azure Trusted Signing are timestamped by Microsoft's RFC3161 timestamp server, so they remain verifiable on Windows after the signing certificate expires.
5. **Release environment gate** — the Windows signing job won't run without approval from two reviewers, and only from `main`.
6. **Duplicate tag check** — the release workflow fails if the tag already exists.

---

## Further Reading

- [CHANGELOG.md](../CHANGELOG.md) — release history
- [VERSIONING.md](../VERSIONING.md) — versioning scheme
- [Sigstore documentation](https://docs.sigstore.dev/) — how keyless signing works
- [SLSA](https://slsa.dev/) — supply chain integrity framework
