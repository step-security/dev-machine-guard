#Requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '..\Dmg.Provisioning.Execution.psm1') -Force
$script:passed=0; $script:failed=0
function Assert-Equal($actual,$expected) { if ($actual -cne $expected) { throw "Expected $expected, received $actual" } }
function Check([string]$name,[scriptblock]$body) {
    try { & $body; $script:passed++; Write-Output "PASS $name" }
    catch { $script:failed++; Write-Output "FAIL $name : $($_.Exception.Message)" }
}
function Snapshot([string]$action) {
    $status='needs_'+$action; $errorCode=''
    if ($action -eq 'noop') { $status='ready' }
    if ($action -eq 'none') { $status='failed';$errorCode='configuration_mismatch' }
    return [pscustomobject]@{Decision=[pscustomobject]@{action=$action;status=$status;error_code=$errorCode;checks=@()};RunningVersion='1.19.0'}
}
function Scenario([string[]]$Actions,[int[]]$Codes,[int]$Budget=300) {
    $s=@{oi=0;ii=0;before=0;after=0;delays=0;budget=$Budget;actions=$Actions;codes=$Codes;order=New-Object Collections.Generic.List[string]}
    $o={ $s.order.Add('observe');$i=[Math]::Min($s.oi,$s.actions.Length-1);$s.oi++; Snapshot $s.actions[$i] }.GetNewClosure()
    $install={param($action) $s.order.Add('install:'+$action);$code=$s.codes[$s.ii];$s.ii++; [pscustomobject]@{TimedOut=($code -eq -1);ExitCode=$code} }.GetNewClosure()
    $before={param($action) $s.order.Add('journal');$s.before++ }.GetNewClosure()
    $after={param($code) $s.order.Add('complete');$s.after++ }.GetNewClosure()
    $remaining={ $s.budget }.GetNewClosure()
    $delay={param($seconds) $s.delays++;$s.budget-=$seconds }.GetNewClosure()
    $r=Invoke-DmgSetupFlow -Observe $o -Install $install -Remaining $remaining -Delay $delay -BeforeMutation $before -AfterMutation $after
    [pscustomobject]@{result=$r;state=$s}
}
Check 'healthy rerun does not invoke installer or journal' {
    $s=Scenario @('noop') @(); Assert-Equal $s.result.exit_code 0; Assert-Equal $s.state.ii 0; Assert-Equal $s.state.before 0
}
Check 'configuration mismatch never invokes installer' {
    $s=Scenario @('none') @(); Assert-Equal $s.result.exit_code 30; Assert-Equal $s.result.error_code 'configuration_mismatch'; Assert-Equal $s.state.ii 0
}
foreach ($action in @('install','upgrade','repair')) {
    Check "$action requires successful observation after exit0" {
        $s=Scenario @($action,'noop') @(0); Assert-Equal $s.result.exit_code 0; Assert-Equal $s.result.action $action
        Assert-Equal ($s.state.order -join ',') ('observe,journal,install:'+$action+',complete,observe')
    }
}
Check 'exit0 with failed postcheck remains non-ready without repair loop' {
    $s=Scenario @('install','repair') @(0); Assert-Equal $s.result.exit_code 30; Assert-Equal $s.result.error_code 'postcheck_failed'; Assert-Equal $s.state.ii 1
}
Check 'permanent MSI failure does not retry' {
    $s=Scenario @('install') @(1603); Assert-Equal $s.result.exit_code 30; Assert-Equal $s.state.ii 1; Assert-Equal $s.state.delays 0
}
foreach ($code in @(3010,1641)) {
    Check "MSI $code requests restart without claiming ready" {
        $s=Scenario @('install') @($code); Assert-Equal $s.result.exit_code 50; Assert-Equal $s.result.reboot_required $true; Assert-Equal $s.state.oi 1
    }
}
Check '1618 retries bounded to three installer attempts' {
    $s=Scenario @('install') @(1618,1618,1618); Assert-Equal $s.result.exit_code 20; Assert-Equal $s.state.ii 3; Assert-Equal $s.state.delays 2
}
Check '1618 reobserves and no-ops when another actor completed setup' {
    $s=Scenario @('install','noop') @(1618); Assert-Equal $s.result.exit_code 0; Assert-Equal $s.result.action 'noop'; Assert-Equal $s.state.ii 1
}
Check '1618 stops on changed tenant instead of reusing stale decision' {
    $s=Scenario @('install','none') @(1618); Assert-Equal $s.result.exit_code 30; Assert-Equal $s.state.ii 1
}
Check '1618 may change next operation after rediscovery' {
    $s=Scenario @('install','repair','noop') @(1618,0); Assert-Equal $s.result.exit_code 0; Assert-Equal $s.result.action 'repair'
}
Check 'timeout leaves pending journal and never retries' {
    $s=Scenario @('install') @(-1); Assert-Equal $s.result.exit_code 40; Assert-Equal $s.state.before 1; Assert-Equal $s.state.after 0; Assert-Equal $s.state.ii 1
}
Check 'expired deadline launches nothing' {
    $s=Scenario @('install') @(0) 0; Assert-Equal $s.result.exit_code 40; Assert-Equal $s.state.ii 0; Assert-Equal $s.state.before 0
}
Check 'insufficient retry budget returns busy' {
    $s=Scenario @('install') @(1618) 4; Assert-Equal $s.result.exit_code 20; Assert-Equal $s.state.ii 1; Assert-Equal $s.state.delays 0
}
Check 'install arguments quote paths and contain no credential values' {
    $args=Get-DmgMsiArguments install 'C:\safe folder\agent.msi' 'C:\safe folder\bootstrap.json'
    Assert-Equal $args '/i "C:\safe folder\agent.msi" /qn /norestart REBOOT=ReallySuppress BOOTSTRAPFILE="C:\safe folder\bootstrap.json"'
}
Check 'repair arguments preserve config and use documented maintenance properties' {
    $args=Get-DmgMsiArguments repair 'C:\safe\agent.msi' 'C:\safe\bootstrap.json'
    Assert-Equal $args '/i "C:\safe\agent.msi" /qn /norestart REBOOT=ReallySuppress REINSTALL=ALL REINSTALLMODE=omus'
}
Check 'argument injection rejected' {
    $rejected=$false;try { $null=Get-DmgMsiArguments install 'C:\a" FORCE=1' 'C:\config.json' } catch { $rejected=$true }; Assert-Equal $rejected $true
}
Check 'unknown completion blocks same-boot mutation regardless of client PID' {
    Assert-Equal (Get-DmgRecoveryGate @{schema_version=1;phase='pending';boot_id='2026-11-09T00:00:00.0000000Z';pid=0} '2026-11-09T00:00:00.0000000Z') 'uncertain'
}
Check 'reboot requirement persists across same-boot rerun' {
    Assert-Equal (Get-DmgRecoveryGate @{schema_version=1;phase='restart_required';boot_id='2026-11-09T00:00:00.0000000Z'} '2026-11-09T00:00:00.0000000Z') 'restart_required'
}
Check 'new boot permits actual rediscovery rather than cached readiness' {
    Assert-Equal (Get-DmgRecoveryGate @{schema_version=1;phase='pending';boot_id='2026-11-09T00:00:00.0000000Z'} '2026-11-09T01:00:00.0000000Z') 'continue'
}
Check 'known completed operation allows reobservation in same boot' {
    Assert-Equal (Get-DmgRecoveryGate @{schema_version=1;phase='completed';boot_id='2026-11-09T00:00:00.0000000Z'} '2026-11-09T00:00:00.0000000Z') 'continue'
}
Check 'unknown recovery schema fails closed' {
    $rejected=$false;try { $null=Get-DmgRecoveryGate @{schema_version=2;phase='completed';boot_id='2026-11-09T00:00:00.0000000Z'} '2026-11-09T00:00:00.0000000Z' } catch { $rejected=$true }; Assert-Equal $rejected $true
}
Check 'atomic journal replacement leaves latest parseable state' {
    $scratch=Join-Path ([IO.Path]::GetTempPath()) ('dmg-journal-'+[guid]::NewGuid().ToString('N'))
    $null=[IO.Directory]::CreateDirectory($scratch)
    $path=Join-Path $scratch 'operation.json'
    Write-DmgPrivateJson $path @{phase='pending'}
    Write-DmgPrivateJson $path @{phase='completed'}
    Assert-Equal ((Get-Content $path -Raw | ConvertFrom-Json).phase) 'completed'
}
Check 'native child exit captured without Start-Process exit-code ambiguity' {
    $exe=(Get-Process -Id $PID).Path
    $r=Invoke-DmgBoundedProcess -FilePath $exe -Arguments '-NoProfile -NonInteractive -Command "exit 20"' -TimeoutSeconds 10
    Assert-Equal $r.TimedOut $false; Assert-Equal $r.ExitCode 20
}
Check 'read-only child timeout is bounded' {
    $exe=(Get-Process -Id $PID).Path
    $r=Invoke-DmgBoundedProcess -FilePath $exe -Arguments '-NoProfile -NonInteractive -Command "Start-Sleep -Seconds 10"' -TimeoutSeconds 1
    Assert-Equal $r.TimedOut $true
}
Check 'expired deadline must not accept an initially healthy observation' {
    $s=Scenario @('noop') @() 0; Assert-Equal $s.result.exit_code 40; Assert-Equal $s.state.oi 0
}
foreach ($phase in @('initial','postcheck','retry')) {
    Check "deadline expiring during $phase observation cannot return ready" {
        $s=@{budget=20;observations=0;installs=0;phase=$phase}
        $observe={
            $s.observations++
            if ($s.phase -eq 'initial' -or $s.observations -gt 1) { $s.budget=0; return Snapshot 'noop' }
            return Snapshot 'install'
        }.GetNewClosure()
        $remaining={ $s.budget }.GetNewClosure()
        $install={param($action) $s.installs++;$code=0;if($s.phase -eq 'retry'){$code=1618};[pscustomobject]@{TimedOut=$false;ExitCode=$code} }.GetNewClosure()
        $r=Invoke-DmgSetupFlow -Observe $observe -Remaining $remaining -Install $install -Delay {} -BeforeMutation {} -AfterMutation {}
        Assert-Equal $r.exit_code 40
    }
}
Check 'missing boot identity cannot clear uncertain state' {
    $rejected=$false;try { $null=Get-DmgRecoveryGate @{schema_version=1;phase='pending';boot_id='2026-11-09T00:00:00.0000000Z'} '' } catch { $rejected=$true }; Assert-Equal $rejected $true
}
Write-Output "Execution tests: $script:passed passed, $script:failed failed."
if ($script:failed) { exit 1 }
exit 0
