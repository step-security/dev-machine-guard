# StepSecurity Dev Machine Guard — Release Process

This document describes how releases are created, signed, notarized, and verified.

> Back to [README](../README.md) | See also: [CHANGELOG](../CHANGELOG.md) | [Versioning](../VERSIONING.md)

---

## Overview

Releases are a three-phase process, where each phase is its own GitHub Actions workflow:

1. **Build and draft (`release.yml`)**: builds binaries for all platforms, Authenticode-signs the Windows `.exe`s and `.msi`s via Azure Trusted Signing, Sigstore-signs the Linux and Windows artifacts (after Authenticode for Windows, so cosign bundles match the bytes users download), creates a **draft** release with the unsigned macOS binary, and emits SLSA build provenance attestations for every artifact except macOS. The Windows signing job runs in the `release` GitHub Environment, which requires two reviewers and is restricted to `main`.
2. **Sign and notarize macOS (`release-macos.yml`)**: a dispatch-only workflow that downloads the unsigned macOS binary from the draft release, codesigns it with the Apple Developer ID certificate, notarizes it with Apple, then Sigstore-signs and attests the final notarized bytes and uploads them to the draft release. It runs in the `release` environment as well. Because Apple notarization can hang, this is kept separate from `release.yml` so it can be re-run on its own without repeating the build. A companion workflow, `check-notarization-status.yml`, inspects a notarization submission that did not finish in time.
3. **Publish**: mark the draft release as published.

macOS signing runs entirely in GitHub Actions; no local Mac is required. The signing credentials are stored as encrypted secrets in the `release` environment (see [Signing credentials](#signing-credentials-one-time-setup)).

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

**Approval gate**: the Windows signing job waits at the `release` environment, where two reviewers must approve before signing runs. The job won't start until the macOS/Linux portion finishes the draft upload, so reviewers can approve while you move on to the macOS step below.

### 3. Sign and notarize the macOS binary

1. Go to [Actions > Release macOS](https://github.com/step-security/dev-machine-guard/actions/workflows/release-macos.yml)
2. Click **Run workflow** and enter the release tag (e.g. `v1.9.1`)

The workflow will:
- Download `stepsecurity-dev-machine-guard-VERSION-darwin_unnotarized` from the draft release
- Import the Developer ID Application certificate into a temporary keychain
- Codesign the binary with the hardened runtime, a secure timestamp, and a fixed identifier (`stepsecurity-dev-machine-guard`), so the designated requirement stays stable across versions and MDM PPPC/TCC Full Disk Access profiles keep working
- Submit it to Apple for notarization, printing the submission id and waiting up to 5 minutes
- Verify with `spctl`, rename the binary to `stepsecurity-dev-machine-guard-VERSION-darwin`, then Sigstore-sign and attest the notarized bytes
- Upload the notarized binary and its cosign bundle to the draft release, and remove the unsigned `darwin_unnotarized` asset

**Approval gate**: this job also waits at the `release` environment for two reviewers.

**If notarization does not finish within 5 minutes**, the run prints the notary submission id and fails. To recover:

1. Go to [Actions > Check Notarization Status](https://github.com/step-security/dev-machine-guard/actions/workflows/check-notarization-status.yml)
2. Click **Run workflow** and enter the submission id from the failed run. It reports the current status and the notary log.
3. Once the status is `Accepted`, re-run the Release macOS workflow for the same tag. Apple keeps processing server-side, so no resubmission is needed.

### 4. Publish the release

```bash
gh release edit "v${VERSION}" --repo step-security/dev-machine-guard \
  --draft=false --latest
```

---

## Signing credentials (one-time setup)

The macOS workflows read their credentials from secrets in the `release` GitHub Environment. These are configured once and reused for every release.

| Secret | Description |
|--------|-------------|
| `MACOS_CERT_P12_BASE64` | Base64 of the exported Developer ID Application certificate and private key (`.p12`) |
| `MACOS_CERT_PASSWORD` | Password set when exporting the `.p12` |
| `MACOS_NOTARY_API_KEY_P8_BASE64` | Base64 of the App Store Connect API key (`AuthKey_XXXX.p8`) used by `notarytool` |
| `MACOS_NOTARY_KEY_ID` | App Store Connect API key id |
| `MACOS_NOTARY_ISSUER_ID` | App Store Connect issuer id |

To export the certificate from a Mac that already has it installed: open Keychain Access, find **Developer ID Application: Step Security, Inc.** under **My Certificates** (it must have the private key nested under it), right-click and **Export** as a `.p12` with a password, then base64-encode it:

```bash
base64 -i devid.p12 | pbcopy   # paste into the MACOS_CERT_P12_BASE64 secret
```

Create the App Store Connect API key under **Users and Access > Integrations > Keys** with the **Developer** role, which covers notarization. Base64-encode the downloaded `.p8` the same way.

---

## Release Artifacts

Each release includes:

| Artifact | Description |
|----------|-------------|
| `stepsecurity-dev-machine-guard-VERSION-darwin` | Notarized universal macOS binary (amd64 + arm64) |
| `stepsecurity-dev-machine-guard-darwin.bundle` | Sigstore cosign bundle (covers the notarized bytes) |
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
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-darwin" \
  --pattern "stepsecurity-dev-machine-guard-darwin.bundle"

# Verify Apple signature and notarization
codesign --verify --deep --strict "stepsecurity-dev-machine-guard-${VERSION}-darwin"
spctl --assess --type execute "stepsecurity-dev-machine-guard-${VERSION}-darwin"

# Verify Sigstore signature on the notarized binary
cosign verify-blob "stepsecurity-dev-machine-guard-${VERSION}-darwin" \
  --bundle "stepsecurity-dev-machine-guard-darwin.bundle" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp "^https://github.com/step-security/dev-machine-guard/.github/workflows/"

# Verify build provenance
gh attestation verify "stepsecurity-dev-machine-guard-${VERSION}-darwin" \
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

1. **Draft then publish flow**: binaries are uploaded to a draft release, the macOS binary is signed and notarized by the gated `release-macos.yml` workflow, then the release is published. Once published, the release is immutable.
2. **Sigstore transparency log**: every artifact's signature is recorded in the public [Rekor](https://rekor.sigstore.dev/) transparency log. The Windows cosign bundles cover the post-Authenticode bytes and the macOS bundle covers the post-notarization bytes, so they match what users download.
3. **SLSA build provenance** — attestation links the artifact to the exact workflow run, commit SHA, and build environment.
4. **Authenticode + RFC3161 timestamp** — Windows `.exe` and `.msi` signatures from Azure Trusted Signing are timestamped by Microsoft's RFC3161 timestamp server, so they remain verifiable on Windows after the signing certificate expires.
5. **Release environment gate**: the Windows and macOS signing jobs won't run without approval from two reviewers, and only from `main`.
6. **Duplicate tag check** — the release workflow fails if the tag already exists.

---

## Further Reading

- [CHANGELOG.md](../CHANGELOG.md) — release history
- [VERSIONING.md](../VERSIONING.md) — versioning scheme
- [Sigstore documentation](https://docs.sigstore.dev/) — how keyless signing works
- [SLSA](https://slsa.dev/) — supply chain integrity framework
