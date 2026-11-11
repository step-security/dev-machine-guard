#Requires -Version 5.1
<#
.SYNOPSIS
    Dependency-free tests of pure Task Scheduler XML and self-check JSON validation.
.DESCRIPTION
    Runs on Windows PowerShell 5.1 or PowerShell 7. These fixtures do not
    exercise native Windows discovery, Task Scheduler registration, MSI, or ACLs.
    The script performs no installation and creates no fixtures on disk.
#>
[CmdletBinding()]
param(
    [string]$ModulePath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Resolve after parameter binding: Windows PowerShell 5.1 may not populate
# PSScriptRoot while evaluating a default parameter expression.
if ([string]::IsNullOrEmpty($ModulePath)) {
    $ModulePath = Join-Path $PSScriptRoot '..\Dmg.Provisioning.Windows.psm1'
}
Import-Module $ModulePath -Force -ErrorAction Stop

$script:Checks = 0
$script:Failures = 0
$Bootstrap = 'C:\Program Files\StepSecurity\stepsecurity-dev-machine-guard-bootstrap.exe'
$Namespace = 'http://schemas.microsoft.com/windows/2004/02/mit/task'

function Assert-BooleanResult {
    param([string]$Name, [scriptblock]$Operation, [bool]$Expected)
    $script:Checks++
    try {
        $actual = & $Operation
        if (($actual -isnot [bool]) -or ($actual -ne $Expected)) {
            $script:Failures++
            Write-Host ('FAIL: {0}; expected Boolean {1}, got {2}' -f $Name, $Expected, ($actual | Out-String).Trim())
        }
        else { Write-Host ('PASS: ' + $Name) }
    }
    catch {
        $script:Failures++
        Write-Host ('FAIL: {0}; validator threw {1}' -f $Name, $_.Exception.GetType().FullName)
    }
}

function New-TaskFixture {
    param([ValidateSet('Scan', 'Logon', 'Update')][string]$Kind)
    $principal = '<GroupId>S-1-5-4</GroupId>'
    $policy = 'Parallel'
    $limit = 'PT4H30M'
    $runLevel = 'LeastPrivilege'
    $arguments = 'run send-telemetry --install-dir="C:\ProgramData\StepSecurity"'
    $trigger = '<TimeTrigger><Repetition><Interval>PT4H</Interval></Repetition><StartBoundary>2026-11-09T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger>'
    if ($Kind -eq 'Logon') { $trigger = '<LogonTrigger><Enabled>true</Enabled></LogonTrigger>' }
    if ($Kind -eq 'Update') {
        $principal = '<UserId>S-1-5-18</UserId>'
        $policy = 'IgnoreNew'
        $limit = 'PT30M'
        $runLevel = 'HighestAvailable'
        $arguments = 'update'
        $trigger = '<TimeTrigger><Repetition><Interval>PT1H</Interval></Repetition><StartBoundary>2026-11-09T00:00:00</StartBoundary><Enabled>true</Enabled><RandomDelay>PT10M</RandomDelay></TimeTrigger><BootTrigger><Enabled>true</Enabled><Delay>PT15M</Delay></BootTrigger>'
    }
    return @"
<Task version="1.2" xmlns="$Namespace">
  <Triggers>$trigger</Triggers>
  <Principals><Principal id="Author">$principal<RunLevel>$runLevel</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>$policy</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><ExecutionTimeLimit>$limit</ExecutionTimeLimit></Settings>
  <Actions Context="Author"><Exec><Command>$Bootstrap</Command><Arguments>$arguments</Arguments></Exec></Actions>
</Task>
"@
}

$Scan = New-TaskFixture 'Scan'
$Logon = New-TaskFixture 'Logon'
$Update = New-TaskFixture 'Update'
$Calendar = $Scan.Replace('<TimeTrigger>', '<CalendarTrigger>').Replace('</TimeTrigger>', '<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay></CalendarTrigger>')
$Cases = @(
    @{ Name = 'scan default recurring task'; Xml = $Scan; Kind = 'Scan'; Expected = $true },
    @{ Name = 'current task schema version'; Xml = $Scan.Replace('version="1.2"', 'version="1.4"'); Kind = 'Scan'; Expected = $true },
    @{ Name = 'scan calendar repetition'; Xml = $Calendar; Kind = 'Scan'; Expected = $true },
    @{ Name = 'logon interactive task'; Xml = $Logon; Kind = 'Logon'; Expected = $true },
    @{ Name = 'update SYSTEM task'; Xml = $Update; Kind = 'Update'; Expected = $true },
    @{ Name = 'quoted bootstrap command'; Xml = $Scan.Replace('<Command>' + $Bootstrap + '</Command>', '<Command>&quot;' + $Bootstrap + '&quot;</Command>'); Kind = 'Scan'; Expected = $true },
    @{ Name = 'bootstrap path case insensitive'; Xml = $Scan.Replace($Bootstrap, $Bootstrap.ToUpperInvariant()); Kind = 'Scan'; Expected = $true },
    @{ Name = 'canonical INTERACTIVE principal'; Xml = $Logon.Replace('S-1-5-4', 'NT AUTHORITY\INTERACTIVE'); Kind = 'Logon'; Expected = $true },
    @{ Name = 'bare INTERACTIVE principal'; Xml = $Scan.Replace('S-1-5-4', 'INTERACTIVE'); Kind = 'Scan'; Expected = $true },
    @{ Name = 'canonical SYSTEM principal'; Xml = $Update.Replace('S-1-5-18', 'NT AUTHORITY\SYSTEM'); Kind = 'Update'; Expected = $true },
    @{ Name = 'bare SYSTEM principal'; Xml = $Update.Replace('S-1-5-18', 'SYSTEM'); Kind = 'Update'; Expected = $true },
    @{ Name = 'omitted enabled settings retain default'; Xml = $Scan.Replace('<Enabled>true</Enabled>', ''); Kind = 'Scan'; Expected = $true },
    @{ Name = 'one minute scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'PT1M' + '</Interval>'); Kind = 'Scan'; Expected = $true },
    @{ Name = '365 day structural scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'P365D' + '</Interval>'); Kind = 'Scan'; Expected = $true },
    @{ Name = 'missing namespace'; Xml = $Scan.Replace(' xmlns="' + $Namespace + '"', ''); Kind = 'Scan'; Expected = $false },
    @{ Name = 'wrong namespace'; Xml = $Scan.Replace($Namespace, 'https://untrusted.invalid/task'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'logon restricted to one user'; Xml = $Logon.Replace('<LogonTrigger>', '<LogonTrigger><UserId>DOMAIN\Alice</UserId>'); Kind = 'Logon'; Expected = $false },
    @{ Name = 'mismatched action principal context'; Xml = $Scan.Replace('Context="Author"', 'Context="Other"'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'missing update run level'; Xml = $Update.Replace('<RunLevel>HighestAvailable</RunLevel>', ''); Kind = 'Update'; Expected = $false },
    @{ Name = 'missing task version'; Xml = $Scan.Replace(' version="1.2"', ''); Kind = 'Scan'; Expected = $false },
    @{ Name = 'malformed XML'; Xml = '<Task><broken>'; Kind = 'Scan'; Expected = $false },
    @{ Name = 'empty XML'; Xml = ''; Kind = 'Scan'; Expected = $false },
    @{ Name = 'wrong task root'; Xml = $Scan.Replace('<Task ', '<Other ').Replace('</Task>', '</Other>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'DOCTYPE is not trusted'; Xml = '<!DOCTYPE Task [<!ENTITY example "not-an-external-resource">]>' + $Scan; Kind = 'Scan'; Expected = $false },
    @{ Name = 'task disabled'; Xml = $Scan.Replace('<Settings><MultipleInstancesPolicy>', '<Settings><Enabled>false</Enabled><MultipleInstancesPolicy>').Replace('<StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled>', '<StartWhenAvailable>true</StartWhenAvailable>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'scan trigger disabled'; Xml = $Scan.Replace('</StartBoundary><Enabled>true</Enabled>', '</StartBoundary><Enabled>false</Enabled>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'logon trigger disabled'; Xml = $Logon.Replace('<LogonTrigger><Enabled>true</Enabled>', '<LogonTrigger><Enabled>false</Enabled>'); Kind = 'Logon'; Expected = $false },
    @{ Name = 'update time trigger disabled'; Xml = $Update.Replace('</StartBoundary><Enabled>true</Enabled>', '</StartBoundary><Enabled>false</Enabled>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'update boot trigger disabled'; Xml = $Update.Replace('<BootTrigger><Enabled>true</Enabled>', '<BootTrigger><Enabled>false</Enabled>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'no scan repetition'; Xml = $Scan.Replace('<Repetition><Interval>PT4H</Interval></Repetition>', ''); Kind = 'Scan'; Expected = $false },
    @{ Name = 'zero scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'PT0S' + '</Interval>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'negative scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + '-PT1H' + '</Interval>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'sub-minute scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'PT1S' + '</Interval>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'over-limit scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'P366D' + '</Interval>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'overflow scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'P999999999D' + '</Interval>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'malformed scan interval'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'four hours' + '</Interval>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'logon task with only time trigger'; Xml = $Scan; Kind = 'Logon'; Expected = $false },
    @{ Name = 'scan task with only logon trigger'; Xml = $Logon; Kind = 'Scan'; Expected = $false },
    @{ Name = 'update missing boot trigger'; Xml = $Update.Replace('<BootTrigger><Enabled>true</Enabled><Delay>PT15M</Delay></BootTrigger>', ''); Kind = 'Update'; Expected = $false },
    @{ Name = 'update wrong repetition'; Xml = $Update.Replace('<Interval>PT1H</Interval>', '<Interval>PT4H</Interval>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'update not start-when-available'; Xml = $Update.Replace('<StartWhenAvailable>true</StartWhenAvailable>', '<StartWhenAvailable>false</StartWhenAvailable>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'scan uses SYSTEM'; Xml = $Scan.Replace('<GroupId>S-1-5-4</GroupId>', '<UserId>S-1-5-18</UserId>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'update uses interactive group'; Xml = $Update.Replace('<UserId>S-1-5-18</UserId>', '<GroupId>S-1-5-4</GroupId>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'user named almost SYSTEM'; Xml = $Update.Replace('S-1-5-18', 'DOMAIN\NOTSYSTEM'); Kind = 'Update'; Expected = $false },
    @{ Name = 'group named almost INTERACTIVE'; Xml = $Scan.Replace('S-1-5-4', 'DOMAIN\INTERACTIVE'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'elevated scan task rejected'; Xml = $Scan.Replace('LeastPrivilege', 'HighestAvailable'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'omitted scan run level defaults to least privilege'; Xml = $Scan.Replace('<RunLevel>LeastPrivilege</RunLevel>', ''); Kind = 'Scan'; Expected = $true },
    @{ Name = 'least privilege update rejected'; Xml = $Update.Replace('HighestAvailable', 'LeastPrivilege'); Kind = 'Update'; Expected = $false },
    @{ Name = 'multiple principals'; Xml = $Scan.Replace('</Principals>', '<Principal id="Other"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'scan serializes users'; Xml = $Scan.Replace('<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>', '<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'update runs parallel'; Xml = $Update.Replace('<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>', '<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'wrong executable'; Xml = $Scan.Replace($Bootstrap, 'C:\Users\Public\agent.exe'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'executable prefix not sufficient'; Xml = $Scan.Replace($Bootstrap, $Bootstrap + '.untrusted.exe'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'command appends arguments'; Xml = $Scan.Replace($Bootstrap, $Bootstrap + ' update'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'scan extra argument'; Xml = $Scan.Replace('</Arguments>', ' --force-scan</Arguments>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'scan wrong data directory'; Xml = $Scan.Replace('C:\ProgramData\StepSecurity', 'C:\Users\Public'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'update extra argument'; Xml = $Update.Replace('<Arguments>update</Arguments>', '<Arguments>update --other</Arguments>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'multiple Exec actions'; Xml = $Scan.Replace('</Actions>', '<Exec><Command>C:\untrusted.exe</Command></Exec></Actions>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'additional COM action'; Xml = $Scan.Replace('</Actions>', '<ComHandler><ClassId>{00000000-0000-0000-0000-000000000001}</ClassId></ComHandler></Actions>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'duplicate Command element'; Xml = $Scan.Replace('</Command>', '</Command><Command>C:\untrusted.exe</Command>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'duplicate Arguments element'; Xml = $Scan.Replace('</Arguments>', '</Arguments><Arguments>update</Arguments>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'duplicate group identity element'; Xml = $Scan.Replace('</GroupId>', '</GroupId><GroupId>S-1-5-32-544</GroupId>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'duplicate user identity element'; Xml = $Update.Replace('</UserId>', '</UserId><UserId>DOMAIN\Alice</UserId>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'expired scan trigger'; Xml = $Scan.Replace('</StartBoundary>', '</StartBoundary><EndBoundary>2000-01-01T00:00:00</EndBoundary>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'future expiration also not persistent'; Xml = $Scan.Replace('</StartBoundary>', '</StartBoundary><EndBoundary>2999-01-01T00:00:00</EndBoundary>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'expired logon trigger'; Xml = $Logon.Replace('<LogonTrigger>', '<LogonTrigger><EndBoundary>2000-01-01T00:00:00</EndBoundary>'); Kind = 'Logon'; Expected = $false },
    @{ Name = 'expired update boot trigger'; Xml = $Update.Replace('<BootTrigger>', '<BootTrigger><EndBoundary>2000-01-01T00:00:00</EndBoundary>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'scan idle gating'; Xml = $Scan.Replace('<Settings>', '<Settings><RunOnlyIfIdle>true</RunOnlyIfIdle>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'logon idle gating'; Xml = $Logon.Replace('<Settings>', '<Settings><RunOnlyIfIdle>true</RunOnlyIfIdle>'); Kind = 'Logon'; Expected = $false },
    @{ Name = 'update idle gating'; Xml = $Update.Replace('<Settings>', '<Settings><RunOnlyIfIdle>true</RunOnlyIfIdle>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'scan network gating'; Xml = $Scan.Replace('<Settings>', '<Settings><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'update network gating'; Xml = $Update.Replace('<Settings>', '<Settings><RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>'); Kind = 'Update'; Expected = $false },
    @{ Name = 'explicit false gating allowed'; Xml = $Scan.Replace('<Settings>', '<Settings><RunOnlyIfIdle>false</RunOnlyIfIdle><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>'); Kind = 'Scan'; Expected = $true },
    @{ Name = 'TimeTrigger cannot use ScheduleByDay'; Xml = $Scan.Replace('<Repetition><Interval>PT4H</Interval></Repetition>', '<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'CalendarTrigger with daily schedule'; Xml = $Calendar.Replace('<Repetition><Interval>PT4H</Interval></Repetition>', ''); Kind = 'Scan'; Expected = $true },
    @{ Name = 'unsupported old task schema'; Xml = $Scan.Replace('version="1.2"', 'version="1.1"'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'unsupported future task schema'; Xml = $Scan.Replace('version="1.2"', 'version="1.5"'); Kind = 'Scan'; Expected = $false },
    @{ Name = 'no Exec action'; Xml = $Scan.Replace('<Exec>', '<ComHandler>').Replace('</Exec>', '</ComHandler>'); Kind = 'Scan'; Expected = $false }
)

foreach ($case in $Cases) {
    Assert-BooleanResult -Name $case.Name -Expected $case.Expected -Operation {
        Test-DmgTaskXml -Xml $case.Xml -Kind $case.Kind -BootstrapPath $Bootstrap
    }
}

$Daily = $Calendar.Replace('<Repetition><Interval>PT4H</Interval></Repetition>', '')
$CadenceCases = @(
    @{ Name = 'configured four hour cadence'; Xml = $Scan; Hours = 4; Expected = $true },
    @{ Name = 'configured four hour calendar repetition'; Xml = $Calendar; Hours = 4; Expected = $true },
    @{ Name = 'configured cadence rejects monthly drift'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'P31D' + '</Interval>'); Hours = 4; Expected = $false },
    @{ Name = 'configured cadence rejects skipped calendar days'; Xml = $Calendar.Replace('<DaysInterval>1</DaysInterval>', '<DaysInterval>2</DaysInterval>'); Hours = 4; Expected = $false },
    @{ Name = 'configured 24 hours becomes daily'; Xml = $Daily; Hours = 24; Expected = $true },
    @{ Name = 'configured 25 hours floors to daily'; Xml = $Daily; Hours = 25; Expected = $true },
    @{ Name = 'configured 48 hours becomes two days'; Xml = $Daily.Replace('<DaysInterval>1</DaysInterval>', '<DaysInterval>2</DaysInterval>'); Hours = 48; Expected = $true },
    @{ Name = 'configured 48 hours rejects every-day drift'; Xml = $Daily; Hours = 48; Expected = $false },
    @{ Name = 'configured daily rejects extra intra-day repetition'; Xml = $Calendar; Hours = 24; Expected = $false },
    @{ Name = 'configured daily needs a CalendarTrigger'; Xml = $Scan.Replace('<Interval>PT4H</Interval>', '<Interval>' + 'P1D' + '</Interval>'); Hours = 24; Expected = $false },
    @{ Name = 'configured huge frequency clamps at 365 days'; Xml = $Daily.Replace('<DaysInterval>1</DaysInterval>', '<DaysInterval>365</DaysInterval>'); Hours = 100000; Expected = $true },
    @{ Name = 'multiple enabled scan triggers rejected'; Xml = $Scan.Replace('</Triggers>', '<LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'); Hours = 4; Expected = $false },
    @{ Name = 'extra disabled scan trigger not active'; Xml = $Scan.Replace('</Triggers>', '<LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers>'); Hours = 4; Expected = $true },
    @{ Name = 'negative expected interval rejected'; Xml = $Scan; Hours = -1; Expected = $false }
)
foreach ($case in $CadenceCases) {
    Assert-BooleanResult -Name $case.Name -Expected $case.Expected -Operation {
        Test-DmgTaskXml -Xml $case.Xml -Kind Scan -BootstrapPath $Bootstrap -ExpectedScanHours $case.Hours
    }
}

# Execution budgets must match the scheduler's watchdog + 30 minute policy.
foreach ($kind in @('Scan','Logon','Update')) {
    $xml = New-TaskFixture $kind
    $original = 'PT4H30M'; if ($kind -eq 'Update') { $original = 'PT30M' }
    foreach ($bad in @('PT1S','PT0S','-PT1H','not-a-duration','P3D')) {
        Assert-BooleanResult -Name "$kind rejects execution limit $bad" -Expected $false -Operation {
            Test-DmgTaskXml -Xml $xml.Replace($original, $bad) -Kind $kind -BootstrapPath $Bootstrap
        }
    }
    foreach ($replacement in @('', ('<ExecutionTimeLimit>' + $original + '</ExecutionTimeLimit><ExecutionTimeLimit>PT1S</ExecutionTimeLimit>'))) {
        Assert-BooleanResult -Name "$kind rejects missing or duplicate execution limit" -Expected $false -Operation {
            Test-DmgTaskXml -Xml $xml.Replace('<ExecutionTimeLimit>' + $original + '</ExecutionTimeLimit>', $replacement) -Kind $kind -BootstrapPath $Bootstrap
        }
    }
}
foreach ($kind in @('Scan','Update')) {
    $xml = New-TaskFixture $kind
    Assert-BooleanResult -Name "$kind rejects expired finite repetition" -Expected $false -Operation {
        Test-DmgTaskXml -Xml $xml.Replace('</Repetition>', '<Duration>P1D</Duration></Repetition>').Replace('2026-11-09', '2000-01-01') -Kind $kind -BootstrapPath $Bootstrap
    }
}
Assert-BooleanResult -Name 'daily calendar can renew finite repetition' -Expected $true -Operation {
    Test-DmgTaskXml -Xml $Calendar.Replace('</Repetition>', '<Duration>P1D</Duration></Repetition>') -Kind Scan -BootstrapPath $Bootstrap -ExpectedScanHours 4
}

$BudgetCases = @(
    @{ Config=''; Env=''; Limit='PT270M' },
    @{ Config='2h'; Env=''; Limit='PT2H30M' },
    @{ Config='45m30s'; Env=''; Limit='PT76M' },
    @{ Config='1h0.1s'; Env=''; Limit='PT91M' },
    @{ Config='+.5h'; Env=''; Limit='PT1H' },
    @{ Config='30.m'; Env=''; Limit='PT1H' },
    @{ Config='1ms'; Env=''; Limit='PT31M' },
    @{ Config='1us'; Env=''; Limit='PT31M' },
    @{ Config=('1'+[char]0xB5+'s'); Env=''; Limit='PT31M' },
    @{ Config=('1'+[char]0x3BC+'s'); Env=''; Limit='PT31M' },
    @{ Config='1ns'; Env=''; Limit='PT31M' },
    @{ Config='0'; Env=''; Limit='PT6H' },
    @{ Config='off'; Env=''; Limit='PT6H' },
    @{ Config='2h'; Env='1h'; Limit='PT90M' },
    @{ Config='2h'; Env='off'; Limit='PT6H' },
    @{ Config='off'; Env='3h'; Limit='PT210M' },
    @{ Config='2h'; Env='invalid'; Limit='PT150M' },
    @{ Config='2h'; Env='-1h'; Limit='PT150M' },
    @{ Config='invalid'; Env='invalid'; Limit='PT270M' },
    @{ Config='0s'; Env=''; Limit='PT270M' },
    @{ Config='0.1ns'; Env=''; Limit='PT270M' },
    @{ Config='OFF'; Env=''; Limit='PT270M' },
    @{ Config='2H'; Env=''; Limit='PT270M' },
    @{ Config=' 2h'; Env=''; Limit='PT270M' },
    @{ Config='2h '; Env=''; Limit='PT270M' },
    @{ Config='1d'; Env=''; Limit='PT270M' },
    @{ Config='9223372036854775808ns'; Env=''; Limit='PT270M' },
    @{ Config='999999999999999999999999999999999999999h'; Env=''; Limit='PT270M' }
)
foreach ($case in $BudgetCases) {
    foreach ($kind in @('Scan','Logon')) {
        Assert-BooleanResult -Name "$kind configured execution budget $($case.Config), env $($case.Env)" -Expected $true -Operation {
            Test-DmgTaskXml -Xml (New-TaskFixture $kind).Replace('PT4H30M', $case.Limit) -Kind $kind -BootstrapPath $Bootstrap -MaxExecutionDuration $case.Config -EnvironmentMaxExecutionDuration $case.Env
        }
    }
}
Assert-BooleanResult -Name 'custom watchdog rejects default task budget drift' -Expected $false -Operation {
    Test-DmgTaskXml -Xml $Scan -Kind Scan -BootstrapPath $Bootstrap -MaxExecutionDuration '2h'
}
Assert-BooleanResult -Name 'updater budget independent of scan watchdog' -Expected $true -Operation {
    Test-DmgTaskXml -Xml $Update -Kind Update -BootstrapPath $Bootstrap -MaxExecutionDuration 'off' -EnvironmentMaxExecutionDuration '1h'
}

$JsonCases = @(
    @{ Name = 'valid machine self-check'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"HOST-123"}'; Allow = $false; Expected = $true },
    @{ Name = 'valid user-scoped SYSTEM self-check'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"","device_id_per_user":true}'; Allow = $true; Expected = $true },
    @{ Name = 'placeholder unknown identity rejected'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"unknown","device_id_per_user":true}'; Allow = $true; Expected = $false },
    @{ Name = 'machine ID allowed in per-user mode'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"HOST-123","device_id_per_user":false}'; Allow = $true; Expected = $true },
    @{ Name = 'per-user exemption not allowed'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"","device_id_per_user":true}'; Allow = $false; Expected = $false },
    @{ Name = 'config_ok false despite process success'; Json = '{"version":"1.18.1","config_ok":false,"device_id":"HOST-123"}'; Allow = $false; Expected = $false },
    @{ Name = 'config_ok string true rejected'; Json = '{"version":"1.18.1","config_ok":"true","device_id":"HOST-123"}'; Allow = $false; Expected = $false },
    @{ Name = 'config_ok integer one rejected'; Json = '{"version":"1.18.1","config_ok":1,"device_id":"HOST-123"}'; Allow = $false; Expected = $false },
    @{ Name = 'config_ok absent'; Json = '{"version":"1.18.1","device_id":"HOST-123"}'; Allow = $false; Expected = $false },
    @{ Name = 'wrong self-check version'; Json = '{"version":"1.18.0","config_ok":true,"device_id":"HOST-123"}'; Allow = $false; Expected = $false },
    @{ Name = 'version must match exactly'; Json = '{"version":"v1.18.1","config_ok":true,"device_id":"HOST-123"}'; Allow = $false; Expected = $false },
    @{ Name = 'version absent'; Json = '{"config_ok":true,"device_id":"HOST-123"}'; Allow = $false; Expected = $false },
    @{ Name = 'empty ID without exemption'; Json = '{"version":"1.18.1","config_ok":true,"device_id":""}'; Allow = $true; Expected = $false },
    @{ Name = 'whitespace ID'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"  "}'; Allow = $false; Expected = $false },
    @{ Name = 'numeric ID rejected'; Json = '{"version":"1.18.1","config_ok":true,"device_id":123}'; Allow = $false; Expected = $false },
    @{ Name = 'string exemption rejected'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"","device_id_per_user":"true"}'; Allow = $true; Expected = $false },
    @{ Name = 'integer exemption rejected'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"","device_id_per_user":1}'; Allow = $true; Expected = $false },
    @{ Name = 'false exemption'; Json = '{"version":"1.18.1","config_ok":true,"device_id":"","device_id_per_user":false}'; Allow = $true; Expected = $false },
    @{ Name = 'malformed JSON'; Json = '{broken'; Allow = $false; Expected = $false },
    @{ Name = 'empty JSON'; Json = ''; Allow = $false; Expected = $false },
    @{ Name = 'null JSON'; Json = 'null'; Allow = $false; Expected = $false },
    @{ Name = 'JSON array rejected'; Json = '[{"version":"1.18.1","config_ok":true,"device_id":"HOST-123"}]'; Allow = $false; Expected = $false },
    @{ Name = 'JSON string rejected'; Json = '"healthy"'; Allow = $false; Expected = $false }
)

foreach ($case in $JsonCases) {
    Assert-BooleanResult -Name $case.Name -Expected $case.Expected -Operation {
        Test-DmgSelfCheck -Json $case.Json -ExpectedVersion '1.18.1' -AllowPerUserIdentity $case.Allow
    }
}

$StateCases = @(
    @{ Name = 'valid bootstrap state pointer'; Json = '{"schema":1,"current":"1.18.1"}'; Expected = $true },
    @{ Name = 'newer integral state schema accepted'; Json = '{"schema":9,"current":"1.18.1","future":{"shape":[1,2]}}'; Expected = $true },
    @{ Name = 'state pointer ignores optional updater evolution'; Json = '{"schema":2,"current":"1.18.1","probation":{"weird":true},"updater":"new-format"}'; Expected = $true },
    @{ Name = 'missing state schema forces fallback'; Json = '{"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'zero state schema forces fallback'; Json = '{"schema":0,"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'negative state schema'; Json = '{"schema":-1,"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'string state schema'; Json = '{"schema":"1","current":"1.18.1"}'; Expected = $false },
    @{ Name = 'floating-point state schema'; Json = '{"schema":1.0,"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'Boolean state schema'; Json = '{"schema":true,"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'state schema field is case sensitive'; Json = '{"Schema":1,"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'missing current version'; Json = '{"schema":1}'; Expected = $false },
    @{ Name = 'current field is case sensitive'; Json = '{"schema":1,"Current":"1.18.1"}'; Expected = $false },
    @{ Name = 'current numeric value'; Json = '{"schema":1,"current":1}'; Expected = $false },
    @{ Name = 'current traversal'; Json = '{"schema":1,"current":"../1.18.1"}'; Expected = $false },
    @{ Name = 'current leading zero rejected'; Json = '{"schema":1,"current":"01.18.1"}'; Expected = $false },
    @{ Name = 'current prerelease rejected'; Json = '{"schema":1,"current":"1.18.1-rc1"}'; Expected = $false },
    @{ Name = 'current uint32 maximum accepted'; Json = '{"schema":1,"current":"4294967295.0.0"}'; Expected = $true },
    @{ Name = 'current uint32 overflow rejected'; Json = '{"schema":1,"current":"4294967296.0.0"}'; Expected = $false },
    @{ Name = 'state singleton array rejected'; Json = '[{"schema":1,"current":"1.18.1"}]'; Expected = $false },
    @{ Name = 'state null rejected'; Json = 'null'; Expected = $false },
    @{ Name = 'state empty rejected'; Json = ''; Expected = $false },
    @{ Name = 'state malformed rejected'; Json = '{broken'; Expected = $false },
    @{ Name = 'state unquoted keys rejected like Go'; Json = '{schema:1,current:"1.18.1"}'; Expected = $false },
    @{ Name = 'state nested unquoted keys rejected like Go'; Json = '{"schema":1,"current":"1.18.1","future":{unquoted:2}}'; Expected = $false },
    @{ Name = 'state duplicate schema rejected conservatively'; Json = '{"schema":0,"schema":1,"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'state duplicate current rejected conservatively'; Json = '{"schema":1,"current":"1.18.0","current":"1.18.1"}'; Expected = $false },
    @{ Name = 'state escaped duplicate current rejected'; Json = '{"schema":1,"current":"1.18.0","curr\u0065nt":"1.18.1"}'; Expected = $false },
    @{ Name = 'state fractional schema rejected'; Json = '{"schema":1.5,"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'state JSON comments rejected like Go'; Json = '{"schema":1,/*comment*/"current":"1.18.1"}'; Expected = $false },
    @{ Name = 'state trailing comma rejected like Go'; Json = '{"schema":1,"current":"1.18.1",}'; Expected = $false },
    @{ Name = 'state nested trailing comma rejected like Go'; Json = '{"schema":1,"current":"1.18.1","future":[1,]}'; Expected = $false },
    @{ Name = 'state extra text may contain escaped quotes and slashes'; Json = '{"schema":1,"current":"1.18.1","future":"https://a.test/\"example\""}'; Expected = $true }
)
foreach ($case in $StateCases) {
    Assert-BooleanResult -Name $case.Name -Expected $case.Expected -Operation {
        Test-DmgStatePointer -Json $case.Json
    }
}

# Access checks model the rights needed by arbitrary interactive users. These
# fixtures test policy only; native ACL enumeration still needs Windows validation.
function New-AccessRule {
    param([string]$Sid = 'S-1-5-32-545', [long]$Rights = 33, [bool]$Allow = $true, [bool]$InheritOnly = $false)
    [pscustomobject]@{ Sid = $Sid; Rights = $Rights; Allow = $Allow; InheritOnly = $InheritOnly }
}
$AccessCases = @(
    @{ Name = 'Users read permits configuration access'; Mask = 1; Rules = @((New-AccessRule -Rights 1)); Expected = $true },
    @{ Name = 'Users read alone cannot execute agent'; Mask = 33; Rules = @((New-AccessRule -Rights 1)); Expected = $false },
    @{ Name = 'Users read execute permits agent access'; Mask = 33; Rules = @((New-AccessRule)); Expected = $true },
    @{ Name = 'Users traverse permits parent traversal'; Mask = 32; Rules = @((New-AccessRule -Rights 32)); Expected = $true },
    @{ Name = 'SYSTEM access alone cannot certify interactive access'; Mask = 1; Rules = @((New-AccessRule -Sid 'S-1-5-18' -Rights 2032127)); Expected = $false },
    @{ Name = 'individual domain allow cannot certify all users'; Mask = 1; Rules = @((New-AccessRule -Sid 'S-1-5-21-100-200-300-1001')); Expected = $false },
    @{ Name = 'broad reader allow masks combine'; Mask = 33; Rules = @((New-AccessRule -Sid 'S-1-5-11' -Rights 1), (New-AccessRule -Sid 'S-1-5-4' -Rights 32)); Expected = $true },
    @{ Name = 'Everyone read permits configuration access'; Mask = 1; Rules = @((New-AccessRule -Sid 'S-1-1-0' -Rights 1)); Expected = $true },
    @{ Name = 'individual user read deny defeats broad allowance'; Mask = 33; Rules = @((New-AccessRule), (New-AccessRule -Sid 'S-1-5-21-100-200-300-1001' -Rights 1 -Allow $false)); Expected = $false },
    @{ Name = 'domain group execute deny defeats broad allowance'; Mask = 33; Rules = @((New-AccessRule), (New-AccessRule -Sid 'S-1-5-21-100-200-300-2001' -Rights 32 -Allow $false)); Expected = $false },
    @{ Name = 'inherit-only allowance does not apply to target'; Mask = 33; Rules = @((New-AccessRule -InheritOnly $true)); Expected = $false },
    @{ Name = 'inherit-only deny does not apply to target'; Mask = 33; Rules = @((New-AccessRule), (New-AccessRule -Allow $false -InheritOnly $true)); Expected = $true },
    @{ Name = 'deny unrelated write right does not block read execute'; Mask = 33; Rules = @((New-AccessRule), (New-AccessRule -Rights 2 -Allow $false)); Expected = $true },
    @{ Name = 'empty access rules fail closed'; Mask = 1; Rules = @(); Expected = $false },
    @{ Name = 'missing SID fails closed'; Mask = 1; Rules = @([pscustomobject]@{ Rights = 1; Allow = $true; InheritOnly = $false }); Expected = $false },
    @{ Name = 'string rights fail closed'; Mask = 1; Rules = @([pscustomobject]@{ Sid = 'S-1-5-32-545'; Rights = '1'; Allow = $true; InheritOnly = $false }); Expected = $false },
    @{ Name = 'string allow fails closed'; Mask = 1; Rules = @([pscustomobject]@{ Sid = 'S-1-5-32-545'; Rights = 1; Allow = 'true'; InheritOnly = $false }); Expected = $false },
    @{ Name = 'missing inheritance flag fails closed'; Mask = 1; Rules = @([pscustomobject]@{ Sid = 'S-1-5-32-545'; Rights = 1; Allow = $true }); Expected = $false },
    @{ Name = 'unsupported access requirement fails closed'; Mask = 0; Rules = @((New-AccessRule)); Expected = $false }
)
foreach ($case in $AccessCases) {
    Assert-BooleanResult -Name $case.Name -Expected $case.Expected -Operation {
        Test-DmgInteractiveAccessRules -Rules $case.Rules -RequiredMask $case.Mask
    }
}

Write-Host ('Checks: {0}; failures: {1}' -f $script:Checks, $script:Failures)
if ($script:Failures -ne 0) { exit 1 }
exit 0
