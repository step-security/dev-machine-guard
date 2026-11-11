#Requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function New-DmgExecutionResult {
    param([int]$ExitCode, [string]$Status, [string]$Action='none', [string]$ErrorCode='', [array]$Checks=@(), [int]$Attempts=0, $MsiExitCode=$null)
    [pscustomobject][ordered]@{
        exit_code=$ExitCode; status=$Status; action=$Action; error_code=$ErrorCode
        checks=@($Checks); attempts=$Attempts; msi_exit_code=$MsiExitCode
        retryable=($ExitCode -eq 20); reboot_required=($ExitCode -eq 50)
    }
}

function Invoke-DmgSetupFlow {
    # Internal dependency seams for deterministic failure tests, never CLI switches.
    param([scriptblock]$Observe, [scriptblock]$Install, [scriptblock]$Remaining,
          [scriptblock]$Delay, [scriptblock]$BeforeMutation, [scriptblock]$AfterMutation,
          [int]$MaxAttempts=3)
    if ((& $Remaining) -le 0) { return New-DmgExecutionResult 40 'uncertain' 'none' 'deadline_exceeded' }
    $snapshot = & $Observe
    if ((& $Remaining) -le 0) { return New-DmgExecutionResult 40 'uncertain' 'none' 'observation_deadline_exceeded' }
    $decision = $snapshot.Decision
    if ($decision.status -eq 'ready') { return New-DmgExecutionResult 0 'ready' 'noop' '' $decision.checks }
    if ($decision.action -notin @('install','upgrade','repair')) {
        return New-DmgExecutionResult 30 'failed' 'none' $decision.error_code $decision.checks
    }
    $action = $decision.action
    for ($attempt=1; $attempt -le $MaxAttempts; $attempt++) {
        if ((& $Remaining) -le 0) { return New-DmgExecutionResult 40 'uncertain' $action 'deadline_exceeded' $decision.checks ($attempt-1) }
        # Journal BEFORE process creation, so a crash between launch and PID write
        # cannot leave an unrecorded installation. Callbacks never log credentials.
        $null = & $BeforeMutation $action
        $native = & $Install $action
        if ($native.TimedOut) {
            return New-DmgExecutionResult 40 'uncertain' $action 'msi_completion_unknown' $decision.checks $attempt
        }
        $code = [int]$native.ExitCode
        $null = & $AfterMutation $code
        if ($code -in @(3010,1641)) { return New-DmgExecutionResult 50 'restart_required' $action 'msi_restart_required' $decision.checks $attempt $code }
        if ($code -eq 1618) {
            if ($attempt -eq $MaxAttempts -or (& $Remaining) -le (5*$attempt)) {
                return New-DmgExecutionResult 20 'busy' $action 'windows_installer_busy' $decision.checks $attempt $code
            }
            $null = & $Delay (5*$attempt)
            # Another installer/updater may have completed during backoff. Never
            # repeat a stale repair or upgrade decision against changed state.
            $snapshot = & $Observe
            if ((& $Remaining) -le 0) { return New-DmgExecutionResult 40 'uncertain' $action 'observation_deadline_exceeded' @() $attempt $code }
            $decision = $snapshot.Decision
            if ($decision.status -eq 'ready') { return New-DmgExecutionResult 0 'ready' 'noop' '' $decision.checks $attempt $code }
            if ($decision.action -notin @('install','upgrade','repair')) {
                return New-DmgExecutionResult 30 'failed' 'none' $decision.error_code $decision.checks $attempt $code
            }
            $action = $decision.action
            continue
        }
        if ($code -ne 0) { return New-DmgExecutionResult 30 'failed' $action 'msi_failed' $decision.checks $attempt $code }
        if ((& $Remaining) -le 0) { return New-DmgExecutionResult 40 'uncertain' $action 'postcheck_deadline_exceeded' $decision.checks $attempt $code }
        $snapshot = & $Observe
        if ((& $Remaining) -le 0) { return New-DmgExecutionResult 40 'uncertain' $action 'postcheck_deadline_exceeded' @() $attempt $code }
        $decision = $snapshot.Decision
        if ($decision.status -eq 'ready') { return New-DmgExecutionResult 0 'ready' $action '' $decision.checks $attempt $code }
        # Best-effort MSI custom actions can fail even with exit0. Do not loop
        # repairs or declare success merely because msiexec succeeded.
        return New-DmgExecutionResult 30 'failed' $action 'postcheck_failed' $decision.checks $attempt $code
    }
}

function ConvertTo-DmgQuotedArgument {
    param([string]$Value)
    # These parameters are filenames, not general Windows command-line syntax.
    # Reject quotes/control characters and trailing slash before adding quotes.
    if ([string]::IsNullOrEmpty($Value) -or $Value -match '["\x00-\x1f]' -or $Value.EndsWith('\')) { throw 'unsafe_argument' }
    return '"' + $Value + '"'
}

function Get-DmgMsiArguments {
    param([ValidateSet('install','upgrade','repair')][string]$Action, [string]$MsiPath, [string]$ConfigPath)
    $args = '/i ' + (ConvertTo-DmgQuotedArgument $MsiPath) + ' /qn /norestart REBOOT=ReallySuppress'
    if ($Action -eq 'repair') { return $args + ' REINSTALL=ALL REINSTALLMODE=omus' }
    return $args + ' BOOTSTRAPFILE=' + (ConvertTo-DmgQuotedArgument $ConfigPath)
}

function Invoke-DmgBoundedProcess {
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds,
          [switch]$Installer, [string]$WorkingDirectory='', [scriptblock]$OnStarted)
    if ($TimeoutSeconds -lt 1) { throw 'deadline_exceeded' }
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=$FilePath; $psi.Arguments=$Arguments
    $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true
    $psi.RedirectStandardOutput=(-not $Installer); $psi.RedirectStandardError=(-not $Installer)
    if ($WorkingDirectory) { $psi.WorkingDirectory=$WorkingDirectory }
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$psi
    try {
        if (-not $process.Start()) { throw 'process_start_failed' }
        if (-not $Installer) {
            $stdout=$process.StandardOutput.ReadToEndAsync()
            $stderr=$process.StandardError.ReadToEndAsync()
        }
        if ($null -ne $OnStarted) { $null = & $OnStarted $process }
        if (-not $process.WaitForExit($TimeoutSeconds*1000)) {
            # Never kill msiexec. Windows Installer may continue in its service
            # even after its client exits. Caller has already journaled intent.
            if (-not $Installer) { $process.Kill() }
            return [pscustomobject]@{TimedOut=$true;ExitCode=$null;Output=''}
        }
        $output=''
        if (-not $Installer) {
            if (-not [Threading.Tasks.Task]::WaitAll(@($stdout,$stderr),1000)) { throw 'process_output_timeout' }
            $output=$stdout.GetAwaiter().GetResult()
            $null=$stderr.GetAwaiter().GetResult()
        }
        if ($output.Length -gt 65536) { throw 'process_output_too_large' }
        return [pscustomobject]@{TimedOut=$false;ExitCode=$process.ExitCode;Output=$output}
    } finally { $process.Dispose() }
}

function Write-DmgPrivateJson {
    param([string]$Path, $Value)
    # Atomic replacement; state is never authority for readiness, only a guard
    # against another mutation. All targets reside in our protected directory.
    $temp=$Path+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    [IO.File]::WriteAllText($temp,($Value | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    if ([IO.File]::Exists($Path)) { [IO.File]::Replace($temp,$Path,[NullString]::Value) }
    else { [IO.File]::Move($temp,$Path) }
}

function Get-DmgRecoveryGate {
    param($State, [string]$BootId)
    $bootTime=[DateTime]::MinValue
    if (-not [DateTime]::TryParseExact($BootId,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$bootTime)) { throw 'invalid_recovery_state' }
    if ($null -eq $State) { return 'continue' }
    if ($State.schema_version -ne 1 -or $State.phase -notin @('pending','completed','restart_required') -or
        -not [DateTime]::TryParseExact([string]$State.boot_id,'o',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind,[ref]$bootTime)) { throw 'invalid_recovery_state' }
    if ($State.phase -eq 'completed') { return 'continue' }
    if ($State.boot_id -cne $BootId) { return 'continue' }
    if ($State.phase -eq 'restart_required') { return 'restart_required' }
    # A same-boot unknown completion is intentionally conservative: service-side
    # installation may outlive the client. A controlled reboot clears this guard;
    # afterwards we reobserve, never trust the old success/cache.
    return 'uncertain'
}

function New-DmgPrivateDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        $security=New-Object Security.AccessControl.DirectorySecurity
        $security.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
        # Framework overload applies ACL at creation; no world-readable window.
        $info=New-Object IO.DirectoryInfo($Path)
        $info.Create($security)
    }
    if (-not (Test-DmgProtectedPath -Path $Path -Confidential)) { throw 'unsafe_work_directory' }
}

function Enter-DmgProvisioningMutex {
    $security=New-Object Security.AccessControl.MutexSecurity
    $security.SetSecurityDescriptorSddlForm('O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)')
    $created=$false
    $mutex=New-Object Threading.Mutex($false,'Global\StepSecurity.DmgProvisioning.v1',[ref]$created,$security)
    try {
        $acl=$mutex.GetAccessControl()
        $trusted=@('S-1-5-18','S-1-5-32-544')
        if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'unsafe_mutex' }
        $raw=New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
        if ($null -eq $raw.DiscretionaryAcl) { throw 'unsafe_mutex' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $trusted -notcontains $rule.IdentityReference.Value) { throw 'unsafe_mutex' }
        }
        $acquired=$false
        try { $acquired=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $acquired=$true }
        if (-not $acquired) { $mutex.Dispose(); return $null }
        return $mutex
    } catch { $mutex.Dispose(); throw }
}

Export-ModuleMember -Function New-DmgExecutionResult, Invoke-DmgSetupFlow, ConvertTo-DmgQuotedArgument, Get-DmgMsiArguments, Invoke-DmgBoundedProcess, Write-DmgPrivateJson, Get-DmgRecoveryGate, New-DmgPrivateDirectory, Enter-DmgProvisioningMutex
