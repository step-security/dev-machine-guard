#Requires -Version 5.1
<#
.SYNOPSIS
    Verify the Ed25519 signature on a StepSecurity dev-machine-guard MSI.

.DESCRIPTION
    Reads the MSI from disk, computes its SHA256, and verifies the
    accompanying .sha256.sig sidecar (an SSH-style Ed25519 signature
    produced by `ssh-keygen -Y sign` and base64-wrapped) against the
    pinned release-operator public key.

    Run this BEFORE invoking `msiexec /i` to confirm the installer bytes
    were produced by StepSecurity and have not been tampered with in
    transit. This is independent of Windows Authenticode trust - it
    cross-checks the same artifact through a second, operator-controlled
    trust anchor.

.PARAMETER Msi
    Path to the *_signed.msi file downloaded from the GitHub release.

.PARAMETER Sig
    Path to the matching *.sha256.sig file. Defaults to "$Msi.sha256.sig".

.EXAMPLE
    .\verify-msi.ps1 -Msi .\stepsecurity-dev-machine-guard-1.11.3-x64_signed.msi

.NOTES
    Requires OpenSSH 8.0+ (for `ssh-keygen -Y verify`):
      * Windows 11 / Windows 10 2004+: built-in
      * Windows 10 1809-1909 / Server 2019: install via "Optional features
        > OpenSSH Client", or use Git for Windows' bundled ssh-keygen.
      * macOS / Linux: ssh-keygen ships with OpenSSH.
#>

param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Msi,

    [Parameter(Position = 1)]
    [string]$Sig
)

$ErrorActionPreference = "Stop"

# ===== Pinned trust anchors (must match the release-signing keypair) =====
$PUBLIC_KEY_SSH      = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILN+WG4lOH/x6MysYOf1oY0PKXLLu9d3ZvQDcvq5Cboi releases@stepsecurity.io"
$SIGNATURE_NAMESPACE = "stepsecurity-mdm-checksum"
$SIGNATURE_IDENTITY  = "releases@stepsecurity.io"

function Write-Info    { param([string]$m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok      { param([string]$m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Fail    { param([string]$m) Write-Host "[FAIL]  $m" -ForegroundColor Red }

if (-not (Test-Path -LiteralPath $Msi)) {
    Write-Fail "MSI not found: $Msi"
    exit 2
}
$Msi = (Resolve-Path -LiteralPath $Msi).Path

if (-not $Sig) { $Sig = "$Msi.sha256.sig" }
if (-not (Test-Path -LiteralPath $Sig)) {
    Write-Fail "Signature sidecar not found: $Sig"
    Write-Info "Download it from the same GitHub release alongside the MSI."
    exit 2
}
$Sig = (Resolve-Path -LiteralPath $Sig).Path

# ----- ssh-keygen probe (OpenSSH 8.0+ required for -Y verify) -----
# Probe order: PATH first, then known fallback locations (Git-for-Windows
# bundles a recent ssh-keygen even on older Windows where the system one
# is too old).
$candidates = @()
$primary = Get-Command ssh-keygen -ErrorAction SilentlyContinue
if ($primary) { $candidates += $primary.Source }
foreach ($p in @(
    "$env:ProgramFiles\Git\usr\bin\ssh-keygen.exe",
    "${env:ProgramFiles(x86)}\Git\usr\bin\ssh-keygen.exe",
    "$env:LOCALAPPDATA\Programs\Git\usr\bin\ssh-keygen.exe",
    "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe"
)) {
    if ($p -and (Test-Path -LiteralPath $p) -and ($candidates -notcontains $p)) {
        $candidates += $p
    }
}

$sshKeygen = $null
foreach ($path in $candidates) {
    $probe = ""
    try { $probe = & $path -Y verify 2>&1 | Out-String } catch { $probe = $_.Exception.Message }
    if ($probe -match "Too few arguments for verify" -or
        $probe -match "missing namespace" -or
        $probe -match "missing argument" -or
        $probe -match "-Y verify ") {
        $sshKeygen = $path
        break
    }
}

if (-not $sshKeygen) {
    Write-Fail "ssh-keygen with -Y verify support (OpenSSH 8.0+) not found."
    Write-Info "Install OpenSSH Client via 'Settings > Apps > Optional features',"
    Write-Info "or install Git for Windows (bundles a recent ssh-keygen)."
    exit 3
}
Write-Info "Using ssh-keygen: $sshKeygen"

# ----- Compute MSI SHA256 -----
$checksum = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToLower()
Write-Info "MSI:      $Msi"
Write-Info "SHA256:   $checksum"

# ----- Stage temp files for ssh-keygen -----
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("verify-msi-" + [IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
$allowedSigners = Join-Path $tmp "allowed_signers"
$sigFile        = Join-Path $tmp "msi.sig"
$msgFile        = Join-Path $tmp "msi.msg"

try {
    # allowed_signers: identity + namespace pin + pubkey. namespaces value
    # MUST be double-quoted - ssh-keygen rejects unquoted values.
    $signersLine = "$SIGNATURE_IDENTITY namespaces=`"$SIGNATURE_NAMESPACE`" $PUBLIC_KEY_SSH`n"
    [IO.File]::WriteAllText($allowedSigners, $signersLine, [Text.UTF8Encoding]::new($false))

    # Decode base64 envelope -> real multi-line SSH signature blob.
    $sigB64 = (Get-Content -LiteralPath $Sig -Raw).Trim()
    try {
        $sigBytes = [Convert]::FromBase64String($sigB64)
    } catch {
        Write-Fail "Sidecar is not valid base64: $Sig"
        exit 4
    }
    [IO.File]::WriteAllBytes($sigFile, $sigBytes)
    if ((Get-Item -LiteralPath $sigFile).Length -eq 0) {
        Write-Fail "Decoded signature is empty"
        exit 4
    }

    # Verified message = raw UTF-8 hex of sha256, no BOM, no trailing newline.
    # Must be byte-identical to what `ssh-keygen -Y sign` consumed at release time.
    [IO.File]::WriteAllBytes($msgFile, [Text.Encoding]::UTF8.GetBytes($checksum))

    # Pipe msg over stdin. Interactive run (this script targets humans),
    # so the SYSTEM-context stdin-pipe bug the dev-machine-guard loader
    # works around does not apply here.
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName               = $sshKeygen
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardInput  = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    # Hand-quoted Arguments string works across PS 5.1 (no ArgumentList
    # property on .NET Framework's ProcessStartInfo) and PS 7+. All paths
    # come from a temp dir under $env:TEMP + GetRandomFileName and won't
    # contain a literal `"` char.
    $psi.Arguments = '-Y verify' +
                     ' -f "' + $allowedSigners + '"' +
                     ' -I "' + $SIGNATURE_IDENTITY + '"' +
                     ' -n "' + $SIGNATURE_NAMESPACE + '"' +
                     ' -s "' + $sigFile + '"'

    $proc = [Diagnostics.Process]::Start($psi)
    $msgBytes = [IO.File]::ReadAllBytes($msgFile)
    $proc.StandardInput.BaseStream.Write($msgBytes, 0, $msgBytes.Length)
    $proc.StandardInput.Close()
    $stdout = $proc.StandardOutput.ReadToEnd()
    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()

    if ($proc.ExitCode -eq 0) {
        Write-Ok "Signature VERIFIED - MSI is authentic and untampered."
        Write-Info "Identity:  $SIGNATURE_IDENTITY"
        Write-Info "Namespace: $SIGNATURE_NAMESPACE"
        exit 0
    } else {
        Write-Fail "Signature verification FAILED (ssh-keygen exit $($proc.ExitCode))"
        if ($stdout) { Write-Host $stdout }
        if ($stderr) { Write-Host $stderr -ForegroundColor Red }
        Write-Fail "DO NOT INSTALL THIS MSI. The bytes do not match the release-signed checksum."
        exit 1
    }
}
finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
