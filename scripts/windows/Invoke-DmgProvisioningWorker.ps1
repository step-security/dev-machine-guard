#Requires -Version 5.1
# Internal bounded read-only worker. Never invokes msiexec or edits tasks.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'Dmg.Provisioning.Policy.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Dmg.Provisioning.Windows.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Dmg.Provisioning.Execution.psm1') -Force
try {
    if (-not (Test-DmgProtectedPath -Path $RequestPath -Confidential)) { throw 'worker_request_invalid' }
    $request=Get-Content -LiteralPath $RequestPath -Raw | ConvertFrom-Json
    foreach ($path in @($request.MsiPath,$request.ConfigPath,$request.SignaturePath)) {
        if (-not (Test-DmgProtectedPath -Path $path -Confidential)) { throw 'bundle_path_invalid' }
    }
    $desired=Read-DmgBootstrapConfig -Path $request.ConfigPath
    $hash=(Get-FileHash -LiteralPath $request.MsiPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $configHash=(Get-FileHash -LiteralPath $request.ConfigPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($request.Mode -eq 'validate') {
        $root=Split-Path -Parent $RequestPath
        $sidecar=Get-Item -LiteralPath $request.SignaturePath
        if ($sidecar.Length -gt 16384) { throw 'signature_invalid' }
        try { $decoded=[Convert]::FromBase64String([IO.File]::ReadAllText($sidecar.FullName).Trim()) }
        catch { throw 'signature_invalid' }
        [IO.File]::WriteAllBytes((Join-Path $root 'signature.ssh'),$decoded)
        [IO.File]::WriteAllText((Join-Path $root 'checksum.txt'),$hash,[Text.UTF8Encoding]::new($false))
        $key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILN+WG4lOH/x6MysYOf1oY0PKXLLu9d3ZvQDcvq5Cboi releases@stepsecurity.io'
        [IO.File]::WriteAllText((Join-Path $root 'allowed_signers'),('releases@stepsecurity.io namespaces="stepsecurity-mdm-checksum" '+$key+"`n"),[Text.UTF8Encoding]::new($false))
        # Use the Windows-owned OpenSSH path, never PATH or a staged executable.
        # Fixed file redirection avoids OpenSSH's SYSTEM-context stdin pipe issue.
        # No caller values enter this shell command; working files have fixed names.
        $system=[Environment]::SystemDirectory
        if ($system -notmatch '^[A-Za-z]:\\[A-Za-z0-9 _\\-]+$') { throw 'verifier_unavailable' }
        $ssh=Join-Path $system 'OpenSSH\ssh-keygen.exe'
        if (-not (Test-DmgProtectedPath $ssh)) { throw 'verifier_unavailable' }
        $command='/d /s /c ""'+$ssh+'" -Y verify -f allowed_signers -I releases@stepsecurity.io -n stepsecurity-mdm-checksum -s signature.ssh < checksum.txt"'
        $verification=Invoke-DmgBoundedProcess -FilePath (Join-Path $system 'cmd.exe') -Arguments $command -WorkingDirectory $root -TimeoutSeconds 30
        if ($verification.TimedOut -or $verification.ExitCode -ne 0) { throw 'signature_invalid' }
        $signature=Get-AuthenticodeSignature -LiteralPath $request.MsiPath
        if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) { throw 'authenticode_invalid' }
        # Pinned release signature authenticates the exact bytes. Record its
        # Authenticode subject for installed binary comparison, no user override.
        $package=Get-DmgMsiMetadata -Path $request.MsiPath
        $boot=(Get-CimInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 30).LastBootUpTime.ToUniversalTime().ToString('o')
        $result=[pscustomobject]@{ok=$true;Package=$package;Publisher=$signature.SignerCertificate.Subject;MsiHash=$hash;ConfigHash=$configHash;BootId=$boot}
    } elseif ($request.Mode -eq 'observe') {
        if ($hash -cne $request.MsiHash -or $configHash -cne $request.ConfigHash) { throw 'bundle_changed' }
        $observation=Get-DmgInstalledObservation -PackageTrust $true -DesiredConfig $desired -ExpectedPublisherSubject $request.Publisher
        $decision=Get-DmgProvisioningDecision -Package $request.Package -Observation $observation -DesiredConfig $desired
        # Configuration contains credentials. Only this allowlist crosses the
        # worker boundary; no native diagnostics, config or caught error text.
        $running=''
        if ($observation.RunningVersion -match '^\d+\.\d+\.\d+$') { $running=$observation.RunningVersion }
        $result=[pscustomobject]@{ok=$true;Decision=$decision;RunningVersion=$running}
    } else { throw 'worker_mode_invalid' }
    $result | ConvertTo-Json -Depth 8 -Compress
    exit 0
} catch {
    $allowed=@('worker_request_invalid','bundle_path_invalid','bootstrap_config_invalid','signature_invalid','verifier_unavailable','authenticode_invalid','bundle_changed','worker_mode_invalid')
    $code='worker_validation_failed'
    if ($allowed -ccontains $_.Exception.Message) { $code=$_.Exception.Message }
    [pscustomobject]@{ok=$false;error_code=$code} | ConvertTo-Json -Compress
    exit 10
}
