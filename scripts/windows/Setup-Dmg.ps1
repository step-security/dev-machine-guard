#Requires -Version 5.1
<#
.SYNOPSIS
    Provision a selected Windows multi-session host from explicitly staged files.
.DESCRIPTION
    Run as SYSTEM using 64-bit Windows PowerShell 5.1 after host naming/join.
    No downloads, pool APIs, recurring tasks, automatic reboots or uninstall.
    Calling platform must keep nonzero/absent results unavailable to users.
    See README.md for bundle protection, prerequisites, exits and recovery.
#>
[CmdletBinding()]
param(
    [string]$MsiPath='',
    [string]$ConfigPath='',
    [string]$SignaturePath='',
    [int]$TimeoutSeconds=900,
    [int]$MaxAttempts=3
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# Validate sibling code BEFORE importing it; the entrypoint itself must be
# supplied by the trusted deployment platform.
function Test-DmgScriptPath {
    # Fail closed on reparse points or ACLs granting unsafe write access. Match
    # the updater's root/ancestor masks; creating an unrelated child at C:\ is
    # not itself permission to replace this path. Do not change any ACL here.
    param([string]$Path, [switch]$Confidential)
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        $first = $true
        while ($null -ne $item) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { return $false }
            $mask = 0x500D0046L
            if (-not $first) { $mask = 0x100D0040L }
            $rules = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
            # An empty DACL is safe but inaccessible; a missing DACL is not.
            $raw = New-Object Security.AccessControl.RawSecurityDescriptor($acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All))
            if ($null -eq $raw.DiscretionaryAcl) { return $false }
            foreach ($rule in $rules) {
                if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
                if ($trusted -contains $rule.IdentityReference.Value) { continue }
                $rights = [long]$rule.FileSystemRights
                if (($rights -band $mask) -ne 0) { return $false }
                if ($first -and $Confidential -and ($rights -band 1) -ne 0) { return $false }
            }
            $parent = [IO.Directory]::GetParent($item.FullName)
            if ($null -eq $parent) { break }
            $item = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
            $first = $false
        }
        return $true
    } catch { return $false }
}

$attemptId=[guid]::NewGuid().ToString('N')
$clock=[Diagnostics.Stopwatch]::StartNew()
$mutex=$null; $runRoot=''; $statePath=''
$ctx=@{RunningVersion='';MsiVersion='';MutationPending=$false;BootId=''}
$result=[ordered]@{schema_version=1;attempt_id=$attemptId;status='failed';action='none';msi_version='';running_version='';checks=@();error_code='setup_failed';retryable=$false;reboot_required=$false;attempts=0;msi_exit_code=$null;exit_code=10;result_path='';log_path=''}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess -or
        $PSVersionTable.PSEdition -ne 'Desktop' -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or
        [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'unsupported_context' }
    if ($TimeoutSeconds -lt 30 -or $TimeoutSeconds -gt 3600 -or $MaxAttempts -lt 1 -or $MaxAttempts -gt 3) { throw 'invalid_limits' }
    foreach ($name in @('Setup-Dmg.ps1','Invoke-DmgProvisioningWorker.ps1','Dmg.Provisioning.Execution.psm1','Dmg.Provisioning.Windows.psm1','Dmg.Provisioning.Policy.psm1')) {
        if (-not (Test-DmgScriptPath (Join-Path $PSScriptRoot $name))) { throw 'unsafe_script_path' }
    }
    Import-Module (Join-Path $PSScriptRoot 'Dmg.Provisioning.Windows.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot 'Dmg.Provisioning.Execution.psm1') -Force
    $mutex=Enter-DmgProvisioningMutex
    if ($null -eq $mutex) {
        $result.status='busy'; $result.error_code='provisioning_busy'; $result.retryable=$true; $result.exit_code=20
    } else {
        foreach ($inputPath in @($MsiPath,$ConfigPath,$SignaturePath)) {
            if ($inputPath -notmatch '^[A-Za-z]:\\' -or $inputPath.Substring(2).Contains(':') -or $inputPath -match '["\x00-\x1f]') { throw 'invalid_local_path' }
            if (([IO.DriveInfo]::new($inputPath.Substring(0,3))).DriveType -ne [IO.DriveType]::Fixed) { throw 'invalid_local_path' }
            $file=Get-Item -LiteralPath $inputPath -Force
            if ($file.PSIsContainer -or -not (Test-DmgProtectedPath -Path $file.FullName -Confidential)) { throw 'unsafe_input_path' }
        }
        if ((Get-Item -LiteralPath $MsiPath).Length -gt 536870912 -or (Get-Item -LiteralPath $ConfigPath).Length -gt 1048576 -or (Get-Item -LiteralPath $SignaturePath).Length -gt 16384) { throw 'input_too_large' }
        # This is a fixed private runtime directory, not a caller-selected output
        # path that could overwrite configuration, code or system files.
        $root=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'StepSecurityProvisioning'
        New-DmgPrivateDirectory $root
        $runRoot=Join-Path $root $attemptId
        New-DmgPrivateDirectory $runRoot
        $statePath=Join-Path $root 'operation.json'
        $result.result_path=Join-Path $runRoot 'result.json'
        $result.log_path=Join-Path $runRoot 'events.jsonl'
        $ctx.LogPath=$result.log_path
        $ctx.Events=New-Object Collections.Generic.List[object]
        $stagedMsi=Join-Path $runRoot 'agent.msi'
        $stagedConfig=Join-Path $runRoot 'bootstrap.json'
        $stagedSignature=Join-Path $runRoot 'agent.msi.sha256.sig'
        [IO.File]::Copy($MsiPath,$stagedMsi,$false)
        [IO.File]::Copy($ConfigPath,$stagedConfig,$false)
        [IO.File]::Copy($SignaturePath,$stagedSignature,$false)
        $request=@{Mode='validate';MsiPath=$stagedMsi;ConfigPath=$stagedConfig;SignaturePath=$stagedSignature}
        $ctx.Request=$request; $ctx.RunRoot=$runRoot; $ctx.Clock=$clock; $ctx.Limit=$TimeoutSeconds; $ctx.StatePath=$statePath
        $ctx.Worker=Join-Path $PSScriptRoot 'Invoke-DmgProvisioningWorker.ps1'
        $ctx.PowerShell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
        $invokeWorker={
            $remaining=[int][Math]::Floor($ctx.Limit-$ctx.Clock.Elapsed.TotalSeconds)
            if ($remaining -le 0) { throw 'deadline_exceeded' }
            $path=Join-Path $ctx.RunRoot ('request-'+[guid]::NewGuid().ToString('N')+'.json')
            Write-DmgPrivateJson $path $ctx.Request
            $arguments='-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File '+(ConvertTo-DmgQuotedArgument $ctx.Worker)+' -RequestPath '+(ConvertTo-DmgQuotedArgument $path)
            $native=Invoke-DmgBoundedProcess -FilePath $ctx.PowerShell -Arguments $arguments -TimeoutSeconds ([Math]::Min(120,$remaining))
            if ($native.TimedOut) { throw 'worker_timeout' }
            try { $payload=$native.Output | ConvertFrom-Json } catch { throw 'invalid_worker_result' }
            if ($native.ExitCode -ne 0 -or -not $payload.ok) {
                $allowed=@('worker_request_invalid','bundle_path_invalid','bootstrap_config_invalid','signature_invalid','verifier_unavailable','authenticode_invalid','bundle_changed','worker_validation_failed')
                if ($allowed -ccontains $payload.error_code) { throw $payload.error_code }
                throw 'worker_failed'
            }
            return $payload
        }.GetNewClosure()
        $validated=& $invokeWorker
        $ctx.MsiVersion=$validated.Package.ProductVersion
        $ctx.BootId=$validated.BootId
        if ([version]$ctx.MsiVersion -lt [version]'1.19.0') { throw 'unsupported_package_version' }
        $prior=$null
        if (Test-Path -LiteralPath $statePath) {
            if (-not (Test-DmgProtectedPath -Path $statePath -Confidential) -or (Get-Item -LiteralPath $statePath).Length -gt 65536) { throw 'invalid_recovery_state' }
            try { $prior=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json } catch { throw 'invalid_recovery_state' }
        }
        $gate=Get-DmgRecoveryGate -State $prior -BootId $ctx.BootId
        if ($gate -eq 'uncertain') { throw 'previous_msi_completion_unknown' }
        if ($gate -eq 'restart_required') { throw 'previous_msi_restart_required' }
        $ctx.Request.Mode='observe'
        foreach ($name in @('Package','Publisher','MsiHash','ConfigHash')) { $ctx.Request[$name]=$validated.$name }
        $ctx.InvokeWorker=$invokeWorker
        $observe={
            $snapshot=& $ctx.InvokeWorker
            $ctx.Events.Add([ordered]@{time_utc=[DateTime]::UtcNow.ToString('o');phase='observation';status=$snapshot.Decision.status;action=$snapshot.Decision.action;error_code=$snapshot.Decision.error_code})
            $ctx.RunningVersion=$snapshot.RunningVersion
            return $snapshot
        }.GetNewClosure()
        $before={
            param($action)
            # Recheck immutable copies immediately before launching privileged MSI.
            if ((Get-FileHash $ctx.Request.MsiPath -Algorithm SHA256).Hash -ine $ctx.Request.MsiHash -or
                (Get-FileHash $ctx.Request.ConfigPath -Algorithm SHA256).Hash -ine $ctx.Request.ConfigHash) { throw 'bundle_changed' }
            $ctx.State=@{schema_version=1;phase='pending';boot_id=$ctx.BootId;attempt_id=$attemptId;action=$action;pid=0;process_start_utc=''}
            Write-DmgPrivateJson $ctx.StatePath $ctx.State
            $ctx.MutationPending=$true
            $ctx.Events.Add([ordered]@{time_utc=[DateTime]::UtcNow.ToString('o');phase='msi_start';action=$action})
        }.GetNewClosure()
        $install={
            param($action)
            $remaining=[int][Math]::Floor($ctx.Limit-$ctx.Clock.Elapsed.TotalSeconds)
            $arguments=Get-DmgMsiArguments -Action $action -MsiPath $ctx.Request.MsiPath -ConfigPath $ctx.Request.ConfigPath
            $started={
                param($process)
                $ctx.State.pid=$process.Id
                $ctx.State.process_start_utc=$process.StartTime.ToUniversalTime().ToString('o')
                Write-DmgPrivateJson $ctx.StatePath $ctx.State
            }.GetNewClosure()
            Invoke-DmgBoundedProcess -FilePath (Join-Path ([Environment]::SystemDirectory) 'msiexec.exe') -Arguments $arguments -TimeoutSeconds $remaining -Installer -OnStarted $started
        }.GetNewClosure()
        $after={
            param($code)
            $ctx.State.phase='completed'
            if ($code -in @(3010,1641)) { $ctx.State.phase='restart_required' }
            $ctx.Events.Add([ordered]@{time_utc=[DateTime]::UtcNow.ToString('o');phase='msi_exit';exit_code=$code})
            $ctx.State.exit_code=$code
            Write-DmgPrivateJson $ctx.StatePath $ctx.State
            $ctx.MutationPending=$false
        }.GetNewClosure()
        $remaining={ [int][Math]::Floor($ctx.Limit-$ctx.Clock.Elapsed.TotalSeconds) }.GetNewClosure()
        $flow=Invoke-DmgSetupFlow -Observe $observe -Install $install -Remaining $remaining -Delay {param($seconds) Start-Sleep -Seconds $seconds} -BeforeMutation $before -AfterMutation $after -MaxAttempts $MaxAttempts
        foreach ($property in $flow.PSObject.Properties) { $result[$property.Name]=$property.Value }
    }
} catch {
    $allowed=@('unsupported_context','invalid_limits','unsafe_script_path','unsafe_mutex','invalid_local_path','unsafe_input_path','input_too_large','unsafe_work_directory','worker_request_invalid','bundle_path_invalid','bootstrap_config_invalid','signature_invalid','verifier_unavailable','authenticode_invalid','bundle_changed','worker_validation_failed','unsupported_package_version','invalid_recovery_state','worker_failed','invalid_worker_result','worker_timeout','deadline_exceeded','previous_msi_completion_unknown','previous_msi_restart_required')
    $result.error_code='setup_failed'
    if ($allowed -ccontains $_.Exception.Message) { $result.error_code=$_.Exception.Message }
    if ($ctx.MutationPending -or $result.error_code -in @('worker_timeout','deadline_exceeded','previous_msi_completion_unknown')) {
        $result.status='uncertain'; $result.exit_code=40
    } elseif ($result.error_code -eq 'previous_msi_restart_required') {
        $result.status='restart_required'; $result.exit_code=50; $result.reboot_required=$true
    }
} finally {
    $result.msi_version=$ctx.MsiVersion; $result.running_version=$ctx.RunningVersion
    if ($result.result_path) {
        try {
            $ctx.Events.Add([ordered]@{time_utc=[DateTime]::UtcNow.ToString('o');phase='result';status=$result.status;error_code=$result.error_code;exit_code=$result.exit_code})
            $lines=@($ctx.Events | ForEach-Object { $_ | ConvertTo-Json -Compress })
            [IO.File]::WriteAllLines($result.log_path,$lines,[Text.UTF8Encoding]::new($false))
            Write-DmgPrivateJson $result.result_path $result
        }
        catch { $result.status='failed'; $result.error_code='result_write_failed'; $result.exit_code=30 }
    }
    if ($null -ne $mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }
}
$result | ConvertTo-Json -Depth 8 -Compress
exit $result.exit_code
