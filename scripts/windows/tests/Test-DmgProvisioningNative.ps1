#Requires -Version 5.1
<#
.SYNOPSIS
    Non-installing native regression checks on a Windows VM with DMG installed.
.DESCRIPTION
    Reads Windows Installer registration/cached MSI metadata and checks rejection
    of an unverified bundle. Cached MSI metadata is NOT package signature proof.
    This is not a successful provisioning or AVD session test.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Native test requires Windows.' }
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Native test requires SYSTEM.' }
Import-Module (Join-Path $PSScriptRoot '..\Dmg.Provisioning.Windows.psm1') -Force
$module = Get-Module Dmg.Provisioning.Windows
$product = & $module { Get-DmgInstalledProduct }
if ($null -eq $product -or $product -is [array]) { throw 'Expected one installed DMG product for this test.' }
Write-Output 'PASS: native installed-product discovery returns one product'
$metadata = & $module {
    param($ProductCode)
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try { $cached = $installer.ProductInfo($ProductCode, 'LocalPackage') }
    finally { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
    Get-DmgMsiMetadata -Path $cached
} $product.ProductCode
# COM Execute/Close return null variants on PS5.1. Without explicit suppression,
# six property reads prepend twelve nulls and turn this result into an array.
if ($metadata -is [array] -or $metadata -isnot [pscustomobject]) { throw 'MSI metadata must be one object, with no COM pipeline values.' }
if ($metadata.ProductCode -ine $product.ProductCode -or $metadata.ProductVersion -cne $product.ProductVersion) { throw 'Cached metadata does not match installed registration.' }
Write-Output 'PASS: cached MSI metadata is one matching object, without COM null outputs'
$observation = Get-DmgInstalledObservation -PackageTrust $false -DesiredConfig @{} -ExpectedPublisherSubject ''
if ($observation -is [array] -or $observation.Installed -or $observation.ObservationError) { throw 'Unexpected untrusted-bundle observation shape.' }
$context = @($observation.Checks | Where-Object { $_.Name -ceq 'Context' })
$trust = @($observation.Checks | Where-Object { $_.Name -ceq 'PackageTrust' })
if ($context.Count -ne 1 -or -not $context[0].Passed -or $trust.Count -ne 1 -or $trust[0].Passed) { throw 'An unverified bundle must fail the trust preflight.' }
Write-Output 'PASS: real SYSTEM context still rejects an unverified package'
Write-Output 'Native checks: 3 passed, 0 failed.'
exit 0
