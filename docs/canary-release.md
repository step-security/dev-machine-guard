# Canary Releases

Canary builds are **internal pre-releases** used to test changes before cutting a real release. They build, smoke-test, sign, and publish artifacts for **Linux and macOS only** — Windows and Apple notarization are deliberately skipped to keep the loop fast.

> Back to [README](../README.md) | See also: [release-process.md](release-process.md)

---

## What's different from a real release

| | Real release (`Release` workflow) | Canary (`Canary Release` workflow) |
|---|---|---|
| Platforms | macOS + Windows + Linux | macOS + Linux |
| Version source | `internal/buildinfo/version.go` (must be bumped) | `version.go` value + `-canary.<run>.<sha>` (no bump) |
| Git tag | `v1.11.1` (semver) | `canary-<run>-<sha>` (lightweight) |
| Draft → publish | Draft, manually notarized, then published | Published immediately as `prerelease` |
| macOS signing | Apple Developer ID + notarization (manual) | Ad-hoc `codesign -s -` (CI only) |
| Sigstore cosign | Yes | Yes |
| SLSA attestation | Yes | Yes |
| Marked as `latest` | Yes | No |
| Who can publish | Anyone with `workflow_dispatch` access | Only reviewers of the `canary-release` GitHub environment |

Production code paths (`.github/workflows/release.yml`, `.goreleaser.yml`, `version.go`, `CHANGELOG.md`) are **not touched** by canaries.

---

## One-time setup (maintainers)

Canary publishing is gated by a GitHub Actions **environment** with required reviewers. Configure it once per repo:

1. Go to **Settings → Environments → New environment**, name it `canary-release`.
2. Under **Deployment protection rules**, enable **Required reviewers** and add the maintainers allowed to cut canaries.
3. Save.

After this, the `build-linux` and `build-darwin` jobs run as soon as the workflow is dispatched, but the `publish` job pauses for reviewer approval before pushing the tag, creating the prerelease, signing, or attesting.

---

## How to cut a canary

1. Go to **Actions → Canary Release** in the GitHub UI.
2. Click **Run workflow** on the branch you want to canary (usually `main`, but any branch works).
3. Wait for `build-linux` and `build-darwin` to finish (~5 min, run in parallel).
4. The `publish` job will pause for approval — an authorized reviewer must approve it in the workflow UI.
5. Once approved, the release appears under [Releases](https://github.com/step-security/dev-machine-guard/releases) marked `Pre-release`.

The canary tag, version, and direct link to the run appear in the release notes.

---

## Versioning

If `version.go` says `1.11.1` and the workflow is run #42 against commit `abc1234`:

- **Version (embedded in binary `--version` output):** `1.11.1-canary.42.abc1234`
- **Git tag:** `canary-42-abc1234` (lightweight, distinct from semver release tags)
- **Artifact prefix:** `stepsecurity-dev-machine-guard-1.11.1-canary.42.abc1234-`

The lightweight tag scheme prevents canary tags from being mistaken for real releases when sorted or listed.

---

## Artifacts published

```
stepsecurity-dev-machine-guard-<version>-darwin           (universal, ad-hoc signed)
stepsecurity-dev-machine-guard-<version>-darwin.bundle
stepsecurity-dev-machine-guard-<version>-linux_amd64
stepsecurity-dev-machine-guard-<version>-linux_amd64.bundle
stepsecurity-dev-machine-guard-<version>-linux_arm64
stepsecurity-dev-machine-guard-<version>-linux_arm64.bundle
stepsecurity-dev-machine-guard-<version>-amd64.deb
stepsecurity-dev-machine-guard-<version>-amd64.deb.bundle
stepsecurity-dev-machine-guard-<version>-arm64.deb
stepsecurity-dev-machine-guard-<version>-arm64.deb.bundle
stepsecurity-dev-machine-guard-<version>-amd64.rpm
stepsecurity-dev-machine-guard-<version>-amd64.rpm.bundle
stepsecurity-dev-machine-guard-<version>-arm64.rpm
stepsecurity-dev-machine-guard-<version>-arm64.rpm.bundle
```

---

## Running a canary

**Linux:**

```bash
VERSION="1.11.1-canary.42.abc1234"
gh release download "canary-42-abc1234" --repo step-security/dev-machine-guard \
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-linux_amd64*"
chmod +x "stepsecurity-dev-machine-guard-${VERSION}-linux_amd64"
./"stepsecurity-dev-machine-guard-${VERSION}-linux_amd64" --version
```

**macOS** (Gatekeeper blocks ad-hoc signed binaries on first launch):

```bash
VERSION="1.11.1-canary.42.abc1234"
gh release download "canary-42-abc1234" --repo step-security/dev-machine-guard \
  --pattern "stepsecurity-dev-machine-guard-${VERSION}-darwin*"
xattr -d com.apple.quarantine "stepsecurity-dev-machine-guard-${VERSION}-darwin"
chmod +x "stepsecurity-dev-machine-guard-${VERSION}-darwin"
./"stepsecurity-dev-machine-guard-${VERSION}-darwin" --version
```

**Verification** works the same way as production — see [release-process.md § Verifying a Release](release-process.md#verifying-a-release).
