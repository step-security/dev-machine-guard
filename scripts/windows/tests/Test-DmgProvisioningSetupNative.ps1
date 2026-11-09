#Requires -Version 5.1
<# Requires SYSTEM, Windows PS5.1 and the real signed v1.18.1 release MSI/sidecar.
   Exercises the public entrypoint without installation. This intentionally tests
   rejection of a trusted old package, not successful installation readiness. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ReleaseMsi, [Parameter(Mandatory=$true)][string]$ReleaseSignature)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$codeRoot=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $codeRoot 'Dmg.Provisioning.Windows.psm1') -Force
Import-Module (Join-Path $codeRoot 'Dmg.Provisioning.Execution.psm1') -Force
$root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) ('DmgProvisioningNativeTest-'+[guid]::NewGuid().ToString('N'))
New-DmgPrivateDirectory $root
$msi=Join-Path $root 'release.msi'
$sig=Join-Path $root 'release.msi.sha256.sig'
[IO.File]::Copy($ReleaseMsi,$msi,$false)
[IO.File]::Copy($ReleaseSignature,$sig,$false)
$config=Join-Path $root 'bootstrap.json'
$secret='native-test-sentinel-not-a-real-api-key'
[IO.File]::WriteAllText($config,('{"customer_id":"provisioning-test","api_endpoint":"https://api.example.test","api_key":"'+$secret+'","device_id":"{hostname}-{user}"}'))
$setup=Join-Path $codeRoot 'Setup-Dmg.ps1'
$exe=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$setupArguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+(ConvertTo-DmgQuotedArgument $setup)+' -MsiPath '+(ConvertTo-DmgQuotedArgument $msi)+' -ConfigPath '+(ConvertTo-DmgQuotedArgument $config)+' -SignaturePath '+(ConvertTo-DmgQuotedArgument $sig)
$passed=0
function Invoke-SetupTest([int]$ExpectedExit,[string]$ExpectedError) {
    $r=Invoke-DmgBoundedProcess -FilePath $exe -Arguments $setupArguments -TimeoutSeconds 150
    if ($r.TimedOut -or $r.ExitCode -ne $ExpectedExit) { throw ('unexpected_setup_exit:'+($r | ConvertTo-Json -Compress)) }
    $j=$r.Output | ConvertFrom-Json
    if ($j.error_code -cne $ExpectedError -or $j.exit_code -ne $ExpectedExit -or $j.status -eq 'ready') { throw ('unexpected_setup_result:'+($j | ConvertTo-Json -Compress)) }
    if ($r.Output.Contains($secret)) { throw 'secret_in_result' }
    if ($j.result_path) {
        $saved=[IO.File]::ReadAllText($j.result_path)
        if ($saved.Contains($secret) -or -not (Test-DmgProtectedPath -Path $j.result_path -Confidential)) { throw 'unsafe_result_file' }
        if (($saved | ConvertFrom-Json).error_code -cne $ExpectedError) { throw 'result_file_mismatch' }
        if ([IO.File]::ReadAllText($j.log_path).Contains($secret) -or -not (Test-DmgProtectedPath -Path $j.log_path -Confidential)) { throw 'unsafe_diagnostic_log' }
    }
    return $j
}
# Same global mutex as production; another process must return busy before any
# validation/mutation. Reentrant same-thread acquisition would not test this.
$mutex=Enter-DmgProvisioningMutex
if ($null -eq $mutex) { throw 'lab_provisioning_already_busy' }
try { $null=Invoke-SetupTest 20 'provisioning_busy'; $passed++; Write-Output 'PASS: competing public setup returns busy' }
finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
$trusted=Invoke-SetupTest 10 'unsupported_package_version'
if ($trusted.msi_version -cne '1.18.1') { throw 'signed_release_metadata_missing' }
$passed++; Write-Output 'PASS: signed release passes trust verification and is rejected before mutation for old version'
# The private bundle is a copy. Mutating the copy never alters the downloaded
# release or any installed files. Detached signature must fail before MSI use.
$stream=[IO.File]::Open($msi,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.WriteByte(0) } finally { $stream.Dispose() }
$null=Invoke-SetupTest 10 'signature_invalid'
$passed++; Write-Output 'PASS: modified package fails signature verification without credential leakage'
[IO.File]::WriteAllText($config,('{"api_key":"'+$secret+'"}'))
$null=Invoke-SetupTest 10 'bootstrap_config_invalid'
$passed++; Write-Output 'PASS: invalid config returns secret-free structured failure'
# Real child behavior with Installer timeout policy, using a short-lived benign
# PowerShell process rather than msiexec. It must survive the parent's timeout.
$marker=Join-Path $root 'child-finished.txt'
$child=Join-Path $root 'finish-later.ps1'
[IO.File]::WriteAllText($child,('Start-Sleep -Seconds 3; [IO.File]::WriteAllText('''+$marker+''',''finished'')'))
$r=Invoke-DmgBoundedProcess -FilePath $exe -Arguments ('-NoProfile -File '+(ConvertTo-DmgQuotedArgument $child)) -TimeoutSeconds 1 -Installer
if (-not $r.TimedOut) { throw 'expected_child_timeout' }
Start-Sleep -Seconds 4
if (-not (Test-Path -LiteralPath $marker)) { throw 'installer_policy_killed_child' }
$passed++; Write-Output 'PASS: installer timeout policy leaves child alive to finish'

# A poisoned writable sibling module must not run before the path check.
$unsafeRoot=Join-Path $root 'untrusted-sibling'
New-DmgPrivateDirectory $unsafeRoot
foreach ($file in @(Get-ChildItem -LiteralPath $codeRoot -File | Where-Object { $_.Extension -in @('.ps1','.psm1') })) {
    [IO.File]::Copy($file.FullName,(Join-Path $unsafeRoot $file.Name),$false)
}
$poisonMarker=Join-Path $root 'module-executed.txt'
$unsafeModule=Join-Path $unsafeRoot 'Dmg.Provisioning.Execution.psm1'
[IO.File]::AppendAllText($unsafeModule,("`n[IO.File]::WriteAllText('"+$poisonMarker+"','executed')`n"))
$acl=Get-Acl -LiteralPath $unsafeModule
$users=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'Modify','Allow')))
Set-Acl -LiteralPath $unsafeModule -AclObject $acl
$originalArguments=$setupArguments
$setupArguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+(ConvertTo-DmgQuotedArgument (Join-Path $unsafeRoot 'Setup-Dmg.ps1'))
try { $null=Invoke-SetupTest 10 'unsafe_script_path' } finally { $setupArguments=$originalArguments }
if (Test-Path -LiteralPath $poisonMarker) { throw 'untrusted_module_executed_before_check' }
$passed++; Write-Output 'PASS: writable sibling module rejected before import/execution'

Write-Output "Setup native tests: $passed passed, 0 failed."
exit 0
