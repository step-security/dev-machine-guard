#Requires -Version 5.1
# Dependency-free policy tests. No MSI, registry, task, network or cloud operations.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
Import-Module (Join-Path $PSScriptRoot '..\Dmg.Provisioning.Policy.psm1') -Force
$script:Passed = 0
$script:Failed = 0
$script:Scratch = Join-Path ([IO.Path]::GetTempPath()) ('dmg-policy-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($script:Scratch)
$script:Package = [PSCustomObject]@{ProductVersion='1.19.0'; ProductCode='{11111111-1111-1111-1111-111111111111}'}
$script:Desired = @{customer_id='example'; api_endpoint='https://api.example.test'; api_key='test-secret-do-not-emit'; device_id='{hostname}'}

function Assert-Equal($Actual, $Expected) {
    if (-not [object]::Equals($Actual,$Expected)) { throw "Expected '$Expected', got '$Actual'." }
}
function Assert-True($Value) { if ($Value -ne $true) { throw 'Expected true.' } }
function Test-Case([string]$CaseTitle, [scriptblock]$Body) {
    try { & $Body; $script:Passed++; Write-Output "PASS $CaseTitle" }
    catch { $script:Failed++; Write-Output "FAIL $CaseTitle : $($_.Exception.Message)" }
}
function New-Observation {
    $checks = @('Context','PackageTrust','Discovery','Layout','RuntimeIntegrity','SelfCheck','Identity',
        'VersionConsistency','ScanTask','LogonTask','UpdateTask','ConfigurationAccess') | ForEach-Object {
            [PSCustomObject]@{Name=$_;Passed=$true}
        }
    return [PSCustomObject]@{
        Installed=$true; ObservationError=$false; ProductVersion='1.19.0';
        ProductCode='{11111111-1111-1111-1111-111111111111}'; RunningVersion='1.19.0';
        Configuration=$script:Desired.Clone(); Checks=@($checks)
    }
}
function Decide($Observation) {
    return Get-DmgProvisioningDecision -Package $script:Package -Observation $Observation -DesiredConfig $script:Desired
}
function Set-FailedCheck($Observation,[string]$Name) {
    ($Observation.Checks | Where-Object { $_.Name -ceq $Name }).Passed = $false
}
function Read-Fixture([string]$Json) {
    $path = Join-Path $script:Scratch ([guid]::NewGuid().ToString('N') + '.json')
    [IO.File]::WriteAllText($path,$Json,[Text.UTF8Encoding]::new($false))
    return Read-DmgBootstrapConfig -Path $path
}
function Assert-Rejected([string]$Json) {
    $caught = $false
    try { $null = Read-Fixture $Json }
    catch {
        $caught = $true
        Assert-Equal $_.Exception.Message 'bootstrap_config_invalid'
    }
    Assert-True $caught
}

Test-Case 'published 1.18.1 package cannot install on an absent host' {
    $oldPackage=[PSCustomObject]@{ProductVersion='1.18.1';ProductCode='{22222222-2222-2222-2222-222222222222}'}
    $o=New-Observation; $o.Installed=$false; $o.ProductVersion=''; $o.ProductCode=''
    $o.RunningVersion=''; $o.Configuration=@{}; $o.Checks=@($o.Checks | Select-Object -First 3)
    $r=Get-DmgProvisioningDecision -Package $oldPackage -Observation $o -DesiredConfig $script:Desired
    Assert-Equal $r.action 'none'; Assert-Equal $r.error_code 'unsupported_package_version'
}
Test-Case 'old staged package is rejected even on a healthy newer host' {
    $oldPackage=[PSCustomObject]@{ProductVersion='1.18.1';ProductCode='{22222222-2222-2222-2222-222222222222}'}
    $o=New-Observation; $o.RunningVersion='1.25.0'
    $r=Get-DmgProvisioningDecision -Package $oldPackage -Observation $o -DesiredConfig $script:Desired
    Assert-Equal $r.action 'none'; Assert-Equal $r.error_code 'unsupported_package_version'
}
Test-Case 'healthy exact version is ready without reinstall' {
    $r = Decide (New-Observation); Assert-Equal $r.status 'ready'; Assert-Equal $r.action 'noop'
}
Test-Case 'newer self-updated runtime is preserved' {
    $o=New-Observation; $o.RunningVersion='1.25.0'; Assert-Equal (Decide $o).action 'noop'
}
Test-Case 'newer installed product can be ready' {
    $o=New-Observation; $o.ProductVersion='1.20.0'; $o.RunningVersion='1.21.0';
    $o.ProductCode='{22222222-2222-2222-2222-222222222222}'; Assert-Equal (Decide $o).status 'ready'
}
Test-Case 'absent installation requires only universal preflights' {
    $o=New-Observation; $o.Installed=$false; $o.ProductVersion=''; $o.ProductCode='';
    $o.RunningVersion=''; $o.Configuration=@{}; $o.Checks=@($o.Checks | Select-Object -First 3)
    Assert-Equal (Decide $o).action 'install'
}
foreach ($name in @('Context','PackageTrust','Discovery')) {
    Test-Case "absent installation cannot bypass $name" {
        $o=New-Observation; $o.Installed=$false; $o.ProductVersion=''; $o.ProductCode='';
        $o.RunningVersion=''; $o.Configuration=@{}; Set-FailedCheck $o $name
        Assert-Equal (Decide $o).action 'none'
    }
}
Test-Case 'residual runtime with absent product is ambiguous' {
    $o=New-Observation; $o.Installed=$false; Assert-Equal (Decide $o).error_code 'ambiguous_installation'
}
Test-Case 'missing observation field fails closed' {
    $o=New-Observation; $o.PSObject.Properties.Remove('RunningVersion'); Assert-Equal (Decide $o).action 'none'
}
Test-Case 'string true cannot substitute for boolean' {
    $o=New-Observation; $o.Installed='true'; Assert-Equal (Decide $o).status 'failed'
}
Test-Case 'observation error prevents mutation' {
    $o=New-Observation; $o.ObservationError=$true; Assert-Equal (Decide $o).error_code 'observation_failed'
}
Test-Case 'missing required check fails closed' {
    $o=New-Observation; $o.Checks=@($o.Checks | Where-Object { $_.Name -ne 'UpdateTask' });
    Assert-Equal (Decide $o).action 'none'
}
Test-Case 'duplicate check fails closed' {
    $o=New-Observation; $o.Checks += [PSCustomObject]@{Name='SelfCheck';Passed=$false};
    Assert-Equal (Decide $o).action 'none'
}
Test-Case 'unknown check names fail closed and are not echoed' {
    $o=New-Observation; $o.Checks += [PSCustomObject]@{Name='test-secret-do-not-emit';Passed=$true}
    $r=Decide $o; Assert-Equal $r.action 'none'; Assert-True (-not (($r | ConvertTo-Json -Depth 8).Contains('test-secret')))
}
foreach ($name in @('ScanTask','LogonTask','UpdateTask')) {
    Test-Case "same product supports repair for missing $name" {
        $o=New-Observation; Set-FailedCheck $o $name; Assert-Equal (Decide $o).action 'repair'
    }
}
foreach ($name in @('Layout','RuntimeIntegrity','SelfCheck','VersionConsistency','ConfigurationAccess')) {
    Test-Case "unsafe $name failure does not request repair" {
        $o=New-Observation; Set-FailedCheck $o $name; Assert-Equal (Decide $o).action 'none'
    }
}
Test-Case 'newer MSI cannot be repaired with older package' {
    $o=New-Observation; $o.ProductVersion='1.20.0'; $o.ProductCode='{22222222-2222-2222-2222-222222222222}'
    $o.RunningVersion='1.21.0'; Set-FailedCheck $o 'UpdateTask'
    Assert-Equal (Decide $o).error_code 'repair_package_too_old'
}
Test-Case 'older MSI with trusted config can upgrade without downgrading runtime' {
    $o=New-Observation; $o.ProductVersion='1.18.0'; $o.ProductCode='{22222222-2222-2222-2222-222222222222}'
    $o.RunningVersion='1.22.0'; Set-FailedCheck $o 'LogonTask'; Assert-Equal (Decide $o).action 'upgrade'
}
Test-Case 'older MSI with corrupt runtime cannot upgrade automatically' {
    $o=New-Observation; $o.ProductVersion='1.18.0'; $o.ProductCode='{22222222-2222-2222-2222-222222222222}'
    Set-FailedCheck $o 'RuntimeIntegrity'; Assert-Equal (Decide $o).action 'none'
}
Test-Case 'same version different product code is not a repair candidate' {
    $o=New-Observation; $o.ProductCode='{22222222-2222-2222-2222-222222222222}'
    Assert-Equal (Decide $o).error_code 'product_identity_mismatch'
}
Test-Case 'same product code cannot claim a different version' {
    $o=New-Observation; $o.ProductVersion='1.18.0'; Assert-Equal (Decide $o).error_code 'product_identity_mismatch'
}
Test-Case 'runtime below approved baseline is not ready' {
    $o=New-Observation; $o.RunningVersion='1.18.0'; Assert-Equal (Decide $o).error_code 'runtime_below_baseline'
}
Test-Case 'bad version syntax fails closed' {
    $o=New-Observation; $o.RunningVersion='1.19.0-preview'; Assert-Equal (Decide $o).action 'none'
}
Test-Case 'tenant mismatch never causes repair or upgrade' {
    $o=New-Observation; $o.Configuration.customer_id='different'; Assert-Equal (Decide $o).error_code 'configuration_mismatch'
}
Test-Case 'credentials are case-sensitive and never emitted' {
    $o=New-Observation; $o.Configuration.api_key='TEST-SECRET-DO-NOT-EMIT'; $r=Decide $o
    Assert-Equal $r.error_code 'configuration_mismatch'
    Assert-True (-not (($r | ConvertTo-Json -Depth 8).ToLowerInvariant().Contains('test-secret')))
}
Test-Case 'documented defaults and normalized endpoint match' {
    $o=New-Observation; $o.Configuration.api_endpoint=' https://api.example.test/// '
    $o.Configuration.retire_on_uninstall=$false; $o.Configuration.auto_update=$true
    $o.Configuration.multi_user_detection='EDITION'; $o.Configuration.scan_frequency_hours='04'
    $o.Configuration.color_mode='auto'; $o.Configuration.output_format='pretty';
    $o.Configuration.log_level='info'; $o.Configuration.search_dirs=@()
    Assert-Equal (Decide $o).status 'ready'
}
Test-Case 'auto-update opt-out is not silently accepted when default on is desired' {
    $o=New-Observation; $o.Configuration.auto_update=$false; Assert-Equal (Decide $o).status 'failed'; Assert-Equal (Decide $o).action 'none'
}
Test-Case 'unknown observed config cannot be silently ignored' {
    $o=New-Observation; $o.Configuration.future_option='value'; Assert-Equal (Decide $o).action 'none'
}
Test-Case 'automatic detection off without a template cannot provision pooled hosts' {
    $c=$script:Desired.Clone(); $c.Remove('device_id'); $c.multi_user_detection='off'
    Assert-Rejected ($c | ConvertTo-Json)
    $c.device_id=' '; Assert-Rejected ($c | ConvertTo-Json)
}
Test-Case 'explicit machine template cannot enable disabled session detection' {
    $c=$script:Desired.Clone(); $c.multi_user_detection='off'
    Assert-Rejected ($c | ConvertTo-Json)
}
Test-Case 'explicit updater opt-out cannot provision this supported profile' {
    $c=$script:Desired.Clone(); $c.auto_update=$false; Assert-Rejected ($c | ConvertTo-Json)
    $c.auto_update=$true; Assert-True (Read-Fixture ($c | ConvertTo-Json)).auto_update
}
Test-Case 'template literals must follow the agent allowlist and length bound' {
    $c=$script:Desired.Clone(); $c.device_id='pool with space-{hostname}'
    Assert-Rejected ($c | ConvertTo-Json)
    $c.device_id=('a' * 129) + '-{hostname}'; Assert-Rejected ($c | ConvertTo-Json)
}
Test-Case 'valid bootstrap returns hashtable without materializing defaults' {
    $c=Read-Fixture ($script:Desired | ConvertTo-Json); Assert-True ($c -is [hashtable])
    Assert-Equal $c.Count 4; Assert-Equal $c.customer_id 'example'
}
Test-Case 'valid automatic identity and optional arrays survive parsing' {
    $c=$script:Desired.Clone(); $c.Remove('device_id'); $c.search_dirs=@('C:\Tools'); $c.update_lag_behind=2
    $r=Read-Fixture ($c | ConvertTo-Json); Assert-Equal $r.search_dirs[0] 'C:\Tools'; Assert-Equal $r.update_lag_behind 2
}
foreach ($json in @(
    '[]','null','{"api_key":"test-secret-do-not-emit"',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a",}',
    '{customer_id:"x","api_endpoint":"https://a.test","api_key":"a"}',
    '{"customer_id":"x",/*comment*/"api_endpoint":"https://a.test","api_key":"a"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","search_dirs":["C:\\Tools",]}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","api_key":"b"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","API_KEY":"b"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","\u0061pi_key":"b"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","auto_update":"true"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","scan_frequency_hours":4}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","search_dirs":"C:\\Tools"}',
    '{"customer_id":"x","api_endpoint":"http://a.test","api_key":"a"}',
    '{"customer_id":"x","api_endpoint":"https://u:p@a.test","api_key":"a"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","user_id":"alice"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","device_id":"builder"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","device_id":"{user}"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","device_id":"{hostname}-{user}-{unknown}"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","new_option":true}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"{{API_KEY}}"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","device_tag":"space tag"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","multi_user_detection":"invalid"}',
    '{"customer_id":"x","api_endpoint":"https://a.test","api_key":"a","update_lag_behind":1.5}'
)) {
    Test-Case 'invalid bootstrap is rejected without leaking parser input' { Assert-Rejected $json }
}
Test-Case 'quoted string content does not masquerade as duplicate keys' {
    $c=$script:Desired.Clone(); $c.api_key='value with "api_key": "quoted"';
    $r=Read-Fixture ($c | ConvertTo-Json); Assert-Equal $r.api_key $c.api_key
}
Test-Case 'properties with uppercase spelling are unsupported' {
    Assert-Rejected '{"CUSTOMER_ID":"x","api_endpoint":"https://a.test","api_key":"a"}'
}
Write-Output ("Policy tests: {0} passed, {1} failed. Scratch: {2}" -f $script:Passed,$script:Failed,$script:Scratch)
if ($script:Failed -gt 0) { exit 1 }
