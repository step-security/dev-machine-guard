# Pure provisioning policy. No Windows mutation, process execution or telemetry.
# Compatible with Windows PowerShell 5.1. Production observation is a separate seam.
Set-StrictMode -Version 2.0

$script:StringKeys = @('customer_id','api_endpoint','api_key','device_id','device_tag',
    'multi_user_detection','scan_frequency_hours','color_mode','output_format',
    'html_output_file','log_level','install_dir','max_execution_duration','update_mirror_url')
$script:BoolKeys = @('enable_npm_scan','enable_brew_scan','enable_python_scan','enable_runtime_scan',
    'include_tcc_protected','include_network_volumes','use_legacy_node_scan','use_legacy_python_scan',
    'retire_on_uninstall','auto_update')
$script:IntKeys = @('update_lag_behind','update_cooldown_hours')
$script:UniversalChecks = @('Context','PackageTrust','Discovery')
$script:InstalledChecks = @('Layout','RuntimeIntegrity','SelfCheck','Identity','VersionConsistency',
    'ScanTask','LogonTask','UpdateTask','ConfigurationAccess')
$script:TaskChecks = @('ScanTask','LogonTask','UpdateTask')
# Minimum source contract, not a claim that a signed 1.19.0 MSI is released or
# Windows-validated. Published 1.18.1 predates the required machine/user identity diagnostics.
$script:MinimumPackageVersion = [version]'1.19.0'

function Assert-DmgJsonProperties {
    param([string]$Json)
    # ConvertFrom-Json can discard duplicate properties. Scan only depth-one
    # property tokens before parsing; strings, escapes and arrays are respected.
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $depth = 0
    for ($i = 0; $i -lt $Json.Length; $i++) {
        $ch = $Json[$i]
        if ($ch -eq '"') {
            $start = $i
            $i++
            while ($i -lt $Json.Length) {
                if ($Json[$i] -eq '\') { $i += 2; continue }
                if ($Json[$i] -eq '"') { break }
                $i++
            }
            if ($i -ge $Json.Length) { throw 'invalid_config_json' }
            $after = $i + 1
            while ($after -lt $Json.Length -and [char]::IsWhiteSpace($Json[$after])) { $after++ }
            if ($depth -eq 1 -and $after -lt $Json.Length -and $Json[$after] -eq ':') {
                $token = $Json.Substring($start, $i - $start + 1)
                try { $name = ('{"key":' + $token + '}') | ConvertFrom-Json -ErrorAction Stop }
                catch { throw 'invalid_config_json' }
                if (-not $seen.Add([string]$name.key)) { throw 'duplicate_config_property' }
            }
            continue
        }
        if ($ch -eq '/' -or $ch -eq "'") { throw 'invalid_config_json' }
        if ($ch -eq ',') {
            $after = $i + 1
            while ($after -lt $Json.Length -and [char]::IsWhiteSpace($Json[$after])) { $after++ }
            if ($after -lt $Json.Length -and ($Json[$after] -eq '}' -or $Json[$after] -eq ']')) { throw 'invalid_config_json' }
        }
        if ($ch -eq '{' -or $ch -eq '[') { $depth++ }
        elseif ($ch -eq '}' -or $ch -eq ']') { $depth-- }
    }
    return $seen.Count
}

function ConvertTo-DmgValidatedConfig {
    param([System.Collections.IDictionary]$Configuration, [switch]$Installed)
    if ($null -eq $Configuration) { throw 'invalid_config_shape' }
    $result = @{}
    foreach ($keyObject in $Configuration.Keys) {
        if ($keyObject -isnot [string]) { throw 'invalid_config_property' }
        $key = [string]$keyObject
        if ($key -ceq 'user_id') { throw 'pooled_user_override_not_supported' }
        $known = @($script:StringKeys + $script:BoolKeys + $script:IntKeys + @('search_dirs'))
        if (-not ($known -ccontains $key)) { throw 'unsupported_config_property' }
        $value = $Configuration[$key]
        if ($script:StringKeys -ccontains $key) {
            if ($value -isnot [string] -or $value -match '[\x00-\x1f]') { throw 'invalid_config_type' }
            $result[$key] = $value
        }
        elseif ($script:BoolKeys -ccontains $key) {
            if ($value -isnot [bool]) { throw 'invalid_config_type' }
            $result[$key] = $value
        }
        elseif ($script:IntKeys -ccontains $key) {
            if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 0 -or $value -gt [int]::MaxValue) {
                throw 'invalid_config_type'
            }
            $result[$key] = [int]$value
        }
        else {
            if ($value -isnot [array]) { throw 'invalid_config_type' }
            foreach ($entry in $value) {
                if ($entry -isnot [string] -or [string]::IsNullOrWhiteSpace($entry) -or $entry -match '[\x00-\x1f]') {
                    throw 'invalid_config_type'
                }
            }
            $result[$key] = @($value)
        }
    }
    foreach ($key in @('customer_id','api_endpoint','api_key')) {
        if (-not $result.ContainsKey($key) -or [string]::IsNullOrWhiteSpace($result[$key]) -or $result[$key].Contains('{{')) {
            throw 'missing_config_credentials'
        }
    }
    $result['api_endpoint'] = $result['api_endpoint'].Trim().TrimEnd('/')
    foreach ($key in @('api_endpoint','update_mirror_url')) {
        if ($result.ContainsKey($key) -and $result[$key] -ne '') {
            $uri = $null
            if (-not [Uri]::TryCreate($result[$key], [UriKind]::Absolute, [ref]$uri) -or
                $uri.Scheme -ne 'https' -or $uri.Host -eq '' -or $uri.UserInfo -ne '' -or
                $uri.Query -ne '' -or $uri.Fragment -ne '') { throw 'invalid_config_endpoint' }
        }
    }
    foreach ($key in @('device_id','device_tag','multi_user_detection')) {
        if ($result.ContainsKey($key)) { $result[$key] = $result[$key].Trim() }
    }
    if ($result.ContainsKey('device_id')) {
        $id = $result['device_id']
        # Bootstrap omission preserves an existing override. An explicit '-'
        # clears it during MSI configure; an installed config stores empty.
        if ($id -eq '') {
            if (-not $Installed) { throw 'empty_device_id_use_omission_or_reset' }
        }
        elseif ($id -eq '-') {
            if ($Installed) { throw 'unapplied_device_identity_reset' }
        }
        else {
            # Match backend template validation. Shared image bundles
            # additionally forbid literals that would identify every clone.
            $literalPart = $id -replace '(?i)\{(hostname|serial)\}', ''
            if ($id.Length -gt 128 -or $literalPart -cmatch '[^A-Za-z0-9._~\-]' -or
                $id -notmatch '(?i)\{(hostname|serial)\}') {
                throw 'pooled_machine_template_required'
            }
        }
    }
    if ($result.ContainsKey('device_tag') -and $result['device_tag'] -ne '' -and
        $result['device_tag'] -cnotmatch '^[A-Za-z0-9._:/-]{1,64}$') { throw 'invalid_config_tag' }
    if ($result.ContainsKey('multi_user_detection')) {
        $result['multi_user_detection'] = $result['multi_user_detection'].ToLowerInvariant()
        if (@('','edition','users','off') -cnotcontains $result['multi_user_detection']) { throw 'invalid_config_detection' }
    }
    if ($result.ContainsKey('multi_user_detection') -and $result['multi_user_detection'] -eq 'off') {
        throw 'pooled_detection_disabled'
    }
    if ($result.ContainsKey('auto_update') -and -not $result['auto_update']) {
        throw 'pooled_auto_update_required'
    }
    if ($result.ContainsKey('scan_frequency_hours') -and $result['scan_frequency_hours'] -ne '') {
        $hours = 0
        if ($result['scan_frequency_hours'] -notmatch '^[0-9]+$' -or
            -not [int]::TryParse($result['scan_frequency_hours'], [ref]$hours) -or $hours -lt 1) { throw 'invalid_config_frequency' }
        $result['scan_frequency_hours'] = [string]$hours
    }
    foreach ($pair in @(
        @{Key='color_mode'; Values=@('','auto','always','never')},
        @{Key='output_format'; Values=@('','pretty','json','html')},
        @{Key='log_level'; Values=@('','error','warn','warning','info','debug')}
    )) {
        if ($result.ContainsKey($pair.Key) -and $pair.Values -cnotcontains $result[$pair.Key]) { throw 'invalid_config_enum' }
    }
    return $result
}

function Read-DmgBootstrapConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.PSIsContainer -or $item.Length -gt 1048576 -or $item.Length -eq 0) { throw 'invalid_config_file' }
        $json = [IO.File]::ReadAllText($item.FullName)
        $propertyCount = Assert-DmgJsonProperties -Json $json
        if (-not $json.TrimStart().StartsWith('{')) { throw 'invalid_config_shape' }
        $parsed = ConvertFrom-Json -InputObject $json -ErrorAction Stop
        if ($parsed -isnot [PSCustomObject]) { throw 'invalid_config_shape' }
        if (@($parsed.PSObject.Properties).Count -ne $propertyCount) { throw 'invalid_config_json' }
        $values = @{}
        foreach ($property in $parsed.PSObject.Properties) { $values[$property.Name] = $property.Value }
        return ConvertTo-DmgValidatedConfig -Configuration $values
    }
    catch {
        # Never forward parser/native errors: they can include JSON secrets.
        throw 'bootstrap_config_invalid'
    }
}

function Get-DmgComparableConfig {
    param([System.Collections.IDictionary]$Configuration, [switch]$Installed)
    $config = ConvertTo-DmgValidatedConfig -Configuration $Configuration -Installed:$Installed
    # Known effective defaults; tri-state collector choices deliberately remain
    # distinct from an explicit override. Preserve every supported other key.
    $defaults = @{
        device_id=''; device_tag=''; multi_user_detection='edition'; retire_on_uninstall=$false;
        auto_update=$true; scan_frequency_hours='4'; color_mode=''; output_format=''; log_level='';
        update_mirror_url=''; update_lag_behind=0; update_cooldown_hours=0;
        use_legacy_node_scan=$false; use_legacy_python_scan=$false;
        include_tcc_protected=$false; include_network_volumes=$true; enable_runtime_scan=$true;
        html_output_file=''; install_dir=''; max_execution_duration=''
    }
    foreach ($key in $defaults.Keys) {
        if (-not $config.ContainsKey($key) -or ($config[$key] -is [string] -and $config[$key] -eq '')) {
            $config[$key] = $defaults[$key]
        }
    }
    if ($config['device_id'] -eq '-') { $config['device_id'] = '' }
    if ($config['color_mode'] -eq 'auto') { $config['color_mode'] = '' }
    if ($config['output_format'] -eq 'pretty') { $config['output_format'] = '' }
    if ($config['log_level'] -eq 'info') { $config['log_level'] = '' }
    if ($config['log_level'] -eq 'warning') { $config['log_level'] = 'warn' }
    if ($config.ContainsKey('search_dirs') -and @($config['search_dirs']).Count -eq 0) { $config.Remove('search_dirs') }
    return $config
}

function Test-DmgConfigurationMatch {
    param([System.Collections.IDictionary]$Desired, [System.Collections.IDictionary]$Observed)
    $left = Get-DmgComparableConfig -Configuration $Desired
    $right = Get-DmgComparableConfig -Configuration $Observed -Installed
    # An omitted identity is a preserve directive, not a request to clear it.
    # Both sides were validated first, so legacy/user/shared-literal overrides
    # cannot become ready merely because the bootstrap omitted device_id.
    if (-not $Desired.Contains('device_id')) { $left['device_id'] = $right['device_id'] }
    if ($left.Count -ne $right.Count) { return $false }
    foreach ($key in $left.Keys) {
        if (-not $right.ContainsKey($key)) { return $false }
        if ($left[$key] -is [array]) {
            if ($right[$key] -isnot [array] -or $left[$key].Count -ne $right[$key].Count) { return $false }
            for ($i = 0; $i -lt $left[$key].Count; $i++) {
                if (-not [string]::Equals($left[$key][$i],$right[$key][$i],[StringComparison]::Ordinal)) { return $false }
            }
        }
        elseif (-not [object]::Equals($left[$key], $right[$key])) { return $false }
    }
    return $true
}

function Test-DmgProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return $null -ne $Object.PSObject.Properties[$Name]
}

function ConvertTo-DmgVersion {
    param($Value)
    if ($Value -isnot [string] -or $Value -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { throw 'invalid_version' }
    return [version]::Parse($Value)
}

function New-DmgPolicyResult {
    param([string]$Status, [string]$Action, [string]$ErrorCode, [array]$Checks=@())
    return [PSCustomObject][ordered]@{status=$Status; action=$Action; error_code=$ErrorCode; checks=@($Checks)}
}

function Get-DmgProvisioningDecision {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Package,
          [Parameter(Mandatory=$true)]$Observation,
          [Parameter(Mandatory=$true)][System.Collections.IDictionary]$DesiredConfig)
    $safeChecks = @()
    try {
        foreach ($name in @('ProductVersion','ProductCode')) {
            if (-not (Test-DmgProperty $Package $name)) { throw 'invalid_package' }
        }
        if ($Package.ProductCode -isnot [string]) { throw 'invalid_package' }
        $packageVersion = ConvertTo-DmgVersion $Package.ProductVersion
        if ($packageVersion -lt $script:MinimumPackageVersion) {
            return New-DmgPolicyResult 'failed' 'none' 'unsupported_package_version' $safeChecks
        }
        $packageCode = [guid]::Parse($Package.ProductCode)
        if ($packageCode -eq [guid]::Empty) { throw 'invalid_package' }
        $null = ConvertTo-DmgValidatedConfig -Configuration $DesiredConfig
        foreach ($name in @('Installed','ObservationError','ProductVersion','ProductCode','RunningVersion','Configuration','Checks')) {
            if (-not (Test-DmgProperty $Observation $name)) { throw 'incomplete_observation' }
        }
        if ($Observation.Installed -isnot [bool] -or $Observation.ObservationError -isnot [bool] -or
            $Observation.Checks -isnot [array]) { throw 'invalid_observation' }
        $checks = @{}
        $allowed = @($script:UniversalChecks + $script:InstalledChecks)
        foreach ($check in $Observation.Checks) {
            if (-not (Test-DmgProperty $check 'Name') -or -not (Test-DmgProperty $check 'Passed') -or
                $check.Name -isnot [string] -or $check.Passed -isnot [bool] -or
                $allowed -cnotcontains $check.Name -or $checks.ContainsKey($check.Name)) { throw 'invalid_checks' }
            $checks[$check.Name] = $check.Passed
            $safeChecks += [PSCustomObject]@{Name=$check.Name; Passed=$check.Passed}
        }
        $required = @($script:UniversalChecks)
        if ($Observation.Installed) { $required += $script:InstalledChecks }
        foreach ($name in $required) {
            if (-not $checks.ContainsKey($name)) { throw 'missing_check' }
        }
        if ($Observation.ObservationError) { return New-DmgPolicyResult 'failed' 'none' 'observation_failed' $safeChecks }
        foreach ($name in $script:UniversalChecks) {
            if (-not $checks[$name]) { return New-DmgPolicyResult 'failed' 'none' 'preflight_failed' $safeChecks }
        }
        if (-not $Observation.Installed) {
            if (-not [string]::IsNullOrEmpty($Observation.ProductVersion) -or
                -not [string]::IsNullOrEmpty($Observation.ProductCode) -or
                -not [string]::IsNullOrEmpty($Observation.RunningVersion) -or
                ($null -ne $Observation.Configuration -and $Observation.Configuration.Count -ne 0)) {
                return New-DmgPolicyResult 'failed' 'none' 'ambiguous_installation' $safeChecks
            }
            return New-DmgPolicyResult 'needs_install' 'install' '' $safeChecks
        }
        $installedVersion = ConvertTo-DmgVersion $Observation.ProductVersion
        $runningVersion = ConvertTo-DmgVersion $Observation.RunningVersion
        if ($Observation.ProductCode -isnot [string]) { throw 'invalid_product' }
        $installedCode = [guid]::Parse($Observation.ProductCode)
        if ($installedCode -eq [guid]::Empty) { throw 'invalid_product' }
        if ($Observation.Configuration -isnot [System.Collections.IDictionary]) { throw 'invalid_config_shape' }
        if (-not (Test-DmgConfigurationMatch -Desired $DesiredConfig -Observed $Observation.Configuration)) {
            return New-DmgPolicyResult 'failed' 'none' 'configuration_mismatch' $safeChecks
        }
        if (($installedVersion -eq $packageVersion -and $installedCode -ne $packageCode) -or
            ($installedVersion -ne $packageVersion -and $installedCode -eq $packageCode)) {
            return New-DmgPolicyResult 'failed' 'none' 'product_identity_mismatch' $safeChecks
        }
        $failed = @($required | Where-Object { -not $checks[$_] })
        foreach ($name in $failed) {
            if ($script:TaskChecks -cnotcontains $name) {
                return New-DmgPolicyResult 'failed' 'none' 'unsafe_installation_state' $safeChecks
            }
        }
        if ($installedVersion -lt $packageVersion) {
            return New-DmgPolicyResult 'needs_upgrade' 'upgrade' '' $safeChecks
        }
        if ($runningVersion -lt $packageVersion) {
            return New-DmgPolicyResult 'failed' 'none' 'runtime_below_baseline' $safeChecks
        }
        if ($failed.Count -eq 0) { return New-DmgPolicyResult 'ready' 'noop' '' $safeChecks }
        if ($installedVersion -gt $packageVersion) {
            return New-DmgPolicyResult 'failed' 'none' 'repair_package_too_old' $safeChecks
        }
        return New-DmgPolicyResult 'needs_repair' 'repair' '' $safeChecks
    }
    catch {
        # No caught exception text, configuration or native output leaves policy.
        return New-DmgPolicyResult 'failed' 'none' 'invalid_input_or_observation' $safeChecks
    }
}

Export-ModuleMember -Function Read-DmgBootstrapConfig, Get-DmgProvisioningDecision
