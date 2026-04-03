# StepSecurity Dev Machine Guard — Release Process

This document describes how releases are created, signed, and verified.

> Back to [README](../README.md) | See also: [CHANGELOG](../CHANGELOG.md) | [Versioning](../VERSIONING.md)

---

## Overview

Releases are created via a manually triggered GitHub Actions workflow (`workflow_dispatch`) that requires approval from the `release` environment. The workflow uses [GoReleaser](https://goreleaser.com/) to:

1. Read the version from `internal/buildinfo/version.go` (`const Version = "1.9.0"`)
2. Verify the tag does not already exist (immutability)
3. Build platform-specific binaries with GoReleaser
4. Sign the binaries with [Sigstore](https://www.sigstore.dev/) cosign (keyless)
5. Generate SHA256 checksums
6. Create a Git tag and GitHub Release
7. Attach binaries, Sigstore bundles, and checksums as release assets
8. Generate SLSA build provenance attestation

## How to Create a Release

### 1. Bump the version

Update `Version` in `internal/buildinfo/version.go`:

```go
const Version = "1.9.0"
```

Update the [CHANGELOG.md](../CHANGELOG.md) with a new section for the version.

Commit and push to `main`.

### 2. Trigger the release workflow

1. Go to [Actions > Release](https://github.com/step-security/dev-machine-guard/actions/workflows/release.yml)
2. Click **Run workflow**
3. Select the `main` branch
4. Click **Run workflow**

### 3. Approve the release

The workflow uses a GitHub Environment called `release` that requires approval. A designated reviewer must approve the run before it proceeds.

### 4. Verify the release

Once approved, the workflow will create the tag, build the binaries, sign them, create the GitHub Release, and upload the artifacts. Check the [Releases page](https://github.com/step-security/dev-machine-guard/releases) to confirm.

---

## Release Artifacts

Each release includes the following artifacts:

| Artifact | Description |
|----------|-------------|
| `stepsecurity-dev-machine-guard_darwin_amd64` | macOS Intel binary |
| `stepsecurity-dev-machine-guard_darwin_arm64` | macOS Apple Silicon binary |
| `checksums.txt` | SHA256 checksums of all release artifacts |
| `*.bundle` | Sigstore cosign bundles (signature, certificate, and Rekor transparency log entry) |

---

## Verifying a Release

Anyone can verify the authenticity of a release artifact using [cosign](https://docs.sigstore.dev/cosign/system_config/installation/).

### Install cosign

```bash
# macOS
brew install cosign

# Other platforms: https://docs.sigstore.dev/cosign/system_config/installation/
```

### Verify the binary signature

```bash
# Download the release artifacts
gh release download v1.9.0 --repo step-security/dev-machine-guard

# Verify the Sigstore signature (example for Apple Silicon)
cosign verify-blob stepsecurity-dev-machine-guard_darwin_arm64 \
  --bundle stepsecurity-dev-machine-guard_darwin_arm64.bundle \
  --certificate-identity-regexp "github.com/step-security/dev-machine-guard" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

A successful verification confirms:

- The binary was signed by the `step-security/dev-machine-guard` GitHub Actions workflow
- The signature is recorded in the [Rekor transparency log](https://search.sigstore.dev/)
- The binary has not been tampered with since signing

### Verify the checksum

```bash
sha256sum -c checksums.txt
```

### Verify build provenance

```bash
gh attestation verify stepsecurity-dev-machine-guard_darwin_arm64 \
  --repo step-security/dev-machine-guard
```

---

## Immutability Guarantees

Releases are designed to be immutable through multiple layers:

1. **Tag protection** — configure [tag protection rules](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/configuring-tag-protection-rules) in repository settings to prevent tag deletion or overwriting.
2. **Duplicate tag check** — the release workflow fails if the tag already exists, preventing accidental re-releases of the same version.
3. **Sigstore transparency log** — every signature is recorded in the public [Rekor](https://rekor.sigstore.dev/) transparency log. Even if an artifact were replaced, verification against the original log entry would fail.
4. **SLSA build provenance** — the attestation links the artifact to the exact workflow run, commit SHA, and build environment.

---

## Environment Setup

The release workflow requires a GitHub Environment named `release` with required reviewers. To configure:

1. Go to **Settings > Environments** in the repository
2. Create an environment named `release`
3. Enable **Required reviewers** and add the appropriate team members
4. Optionally restrict to the `main` branch under **Deployment branches**

---

## Further Reading

- [CHANGELOG.md](../CHANGELOG.md) — release history
- [VERSIONING.md](../VERSIONING.md) — versioning scheme
- [Sigstore documentation](https://docs.sigstore.dev/) — how keyless signing works
- [SLSA](https://slsa.dev/) — supply chain integrity framework
