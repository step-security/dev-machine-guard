#Requires -Version 5.1
# Windows observations for the provisioning policy. This module never
# installs, repairs, registers tasks, changes configuration, or admits users.
Set-StrictMode -Version Latest

function Get-DmgObjectValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $p = $Object.PSObject.Properties[$Name]
    if ($null -ne $p) { return $p.Value }
    return $null
}

function Test-DmgSelfCheck {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Json, [string]$ExpectedVersion, [bool]$AllowPerUserIdentity = $false)
    try {
        if ($Json.Length -gt 65536 -or -not $Json.TrimStart().StartsWith('{') -or $ExpectedVersion -notmatch '^\d+\.\d+\.\d+$') { return $false }
        $v = ConvertFrom-DmgJsonObject -Json $Json
        $ok = Get-DmgObjectValue $v 'config_ok'
        if ($ok -isnot [bool] -or -not $ok) { return $false }
        if ((Get-DmgObjectValue $v 'version') -cne $ExpectedVersion) { return $false }
        $id = Get-DmgObjectValue $v 'device_id'
        if ($id -isnot [string] -or $id -ceq 'unknown') { return $false }
        if (-not [string]::IsNullOrWhiteSpace($id)) { return $true }
        $perUser = Get-DmgObjectValue $v 'device_id_per_user'
        return ($AllowPerUserIdentity -and $perUser -is [bool] -and $perUser)
    } catch { return $false }
}

function Get-DmgScanExecutionMinutes {
    param([string]$ConfigValue, [string]$EnvironmentValue)
    # Mirror telemetry.ExecutionDeadline: positive Go durations, exact 0/off,
    # env > config > 4h. Scheduler adds 30m and rounds up; disabled gets 6h.
    $units = @{ ns=[decimal]1; us=[decimal]1000; ms=[decimal]1000000; s=[decimal]1000000000; m=[decimal]60000000000; h=[decimal]3600000000000 }
    $units[([char]0xB5).ToString() + 's'] = [decimal]1000
    $units[([char]0x3BC).ToString() + 's'] = [decimal]1000
    $part = '(?<number>(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+))(?<unit>ns|us|\u00b5s|\u03bcs|ms|s|m|h)'
    foreach ($value in @($EnvironmentValue, $ConfigValue, '4h')) {
        if ($value -ceq '0' -or $value -ceq 'off') { return [decimal]360 }
        if ($value -cnotmatch ('\A\+?(?:' + $part + ')+\z')) { continue }
        try {
            $nanos = [decimal]0
            foreach ($piece in [regex]::Matches($value, $part)) {
                $number = [decimal]::Parse($piece.Groups['number'].Value, [Globalization.CultureInfo]::InvariantCulture)
                $nanos += [decimal]::Truncate($number * $units[$piece.Groups['unit'].Value])
            }
            if ($nanos -le 0 -or $nanos -gt [decimal]([long]::MaxValue)) { continue }
            return [decimal]::Ceiling($nanos / [decimal]60000000000) + [decimal]30
        } catch { continue }
    }
}

function Test-DmgTaskXml {
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Xml, [ValidateSet('Scan','Logon','Update')][string]$Kind, [string]$BootstrapPath, [int]$ExpectedScanHours = 0, [string]$MaxExecutionDuration = '', [string]$EnvironmentMaxExecutionDuration = '')
    $reader = $null
    try {
        if ([string]::IsNullOrWhiteSpace($Xml) -or $Xml.Length -gt 262144 -or $ExpectedScanHours -lt 0) { return $false }
        $settings = New-Object System.Xml.XmlReaderSettings
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($Xml)), $settings)
        $doc = New-Object System.Xml.XmlDocument
        $doc.XmlResolver = $null
        $doc.Load($reader)
        if ($doc.DocumentElement.LocalName -cne 'Task' -or $doc.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/windows/2004/02/mit/task') { return $false }
        if ($doc.DocumentElement.GetAttribute('version') -notin @('1.2','1.3','1.4')) { return $false }
        $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
        $ns.AddNamespace('t', $doc.DocumentElement.NamespaceURI)
        foreach ($xpath in @('/t:Task/t:Actions','/t:Task/t:Settings','/t:Task/t:Principals')) {
            if ($doc.SelectNodes($xpath, $ns).Count -ne 1) { return $false }
        }
        foreach ($xpath in @('/t:Task/t:Actions/t:Exec/t:Command','/t:Task/t:Actions/t:Exec/t:Arguments','/t:Task/t:Principals/t:Principal/t:GroupId','/t:Task/t:Principals/t:Principal/t:UserId','/t:Task/t:Principals/t:Principal/t:RunLevel','/t:Task/t:Settings/t:Enabled','/t:Task/t:Settings/t:MultipleInstancesPolicy')) {
            if ($doc.SelectNodes($xpath, $ns).Count -gt 1) { return $false }
        }
        foreach ($xpath in @('/t:Task/t:Settings/t:RunOnlyIfIdle','/t:Task/t:Settings/t:RunOnlyIfNetworkAvailable')) {
            $flag = $doc.SelectSingleNode($xpath, $ns)
            if ($null -ne $flag -and $flag.InnerText -notin @('false','0')) { return $false }
        }
        if ($doc.SelectNodes('/t:Task/t:Triggers/*/t:EndBoundary', $ns).Count -gt 0) { return $false }
        $actions = $doc.SelectNodes('/t:Task/t:Actions/*', $ns)
        if ($actions.Count -ne 1 -or $actions[0].LocalName -cne 'Exec') { return $false }
        $command = $doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Command', $ns)
        $arguments = $doc.SelectSingleNode('/t:Task/t:Actions/t:Exec/t:Arguments', $ns)
        if ($null -eq $command -or $null -eq $arguments) { return $false }
        $cmd = $command.InnerText.Trim()
        if ($cmd.StartsWith('"') -and $cmd.EndsWith('"') -and $cmd.Length -ge 2) { $cmd = $cmd.Substring(1, $cmd.Length - 2) }
        if (-not [string]::Equals($cmd, $BootstrapPath, [StringComparison]::OrdinalIgnoreCase)) { return $false }
        $expected = 'run send-telemetry --install-dir="C:\ProgramData\StepSecurity"'
        if ($Kind -eq 'Update') { $expected = 'update' }
        if ($arguments.InnerText.Trim() -cne $expected) { return $false }
        $principals = $doc.SelectNodes('/t:Task/t:Principals/t:Principal', $ns)
        if ($principals.Count -ne 1) { return $false }
        $principal = $principals[0]
        $context = $doc.SelectSingleNode('/t:Task/t:Actions/@Context', $ns)
        if ($null -ne $context -and $context.Value -cne $principal.GetAttribute('id')) { return $false }
        $isUpdate = $Kind -eq 'Update'
        $sidNode = 't:GroupId'; $otherNode = 't:UserId'
        $validIds = @('S-1-5-4', 'NT AUTHORITY\INTERACTIVE', 'INTERACTIVE')
        if ($isUpdate) { $sidNode = 't:UserId'; $otherNode = 't:GroupId'; $validIds = @('S-1-5-18', 'NT AUTHORITY\SYSTEM', 'SYSTEM') }
        $idNode = $principal.SelectSingleNode($sidNode, $ns)
        if ($null -eq $idNode -or $validIds -notcontains $idNode.InnerText -or $null -ne $principal.SelectSingleNode($otherNode, $ns)) { return $false }
        $level = $principal.SelectSingleNode('t:RunLevel', $ns)
        if ($isUpdate) {
            if ($null -eq $level -or $level.InnerText -cne 'HighestAvailable') { return $false }
        } elseif ($null -ne $level -and $level.InnerText -cne 'LeastPrivilege') { return $false }
        $enabled = $doc.SelectSingleNode('/t:Task/t:Settings/t:Enabled', $ns)
        if ($null -ne $enabled -and $enabled.InnerText -notin @('true','1')) { return $false }
        $policy = $doc.SelectSingleNode('/t:Task/t:Settings/t:MultipleInstancesPolicy', $ns)
        $expectedPolicy = 'Parallel'; if ($isUpdate) { $expectedPolicy = 'IgnoreNew' }
        if ($null -eq $policy -or $policy.InnerText -cne $expectedPolicy) { return $false }
        $limits = $doc.SelectNodes('/t:Task/t:Settings/t:ExecutionTimeLimit', $ns)
        if ($limits.Count -ne 1) { return $false }
        $minutes = [decimal]30
        if (-not $isUpdate) { $minutes = Get-DmgScanExecutionMinutes -ConfigValue $MaxExecutionDuration -EnvironmentValue $EnvironmentMaxExecutionDuration }
        $limit = [System.Xml.XmlConvert]::ToTimeSpan($limits[0].InnerText)
        if ([decimal]$limit.Ticks -ne $minutes * [decimal]600000000) { return $false }
        $triggers = @($doc.SelectNodes('/t:Task/t:Triggers/*', $ns) | Where-Object {
            $e = $_.SelectSingleNode('t:Enabled', $ns)
            $null -eq $e -or $e.InnerText -in @('true','1')
        })
        if ($Kind -eq 'Logon') { return (@($triggers | Where-Object { $_.LocalName -ceq 'LogonTrigger' -and $null -eq $_.SelectSingleNode('t:UserId', $ns) }).Count -gt 0) }
        if ($Kind -eq 'Scan' -and $triggers.Count -ne 1) { return $false }
        $periodic = $false; $boot = $false
        foreach ($trigger in $triggers) {
            if ($trigger.LocalName -ceq 'BootTrigger') { $boot = $true }
            if ($trigger.LocalName -notin @('TimeTrigger','CalendarTrigger')) { continue }
            foreach ($xpath in @('t:Repetition', 't:Repetition/t:Interval', 't:ScheduleByDay', 't:ScheduleByDay/t:DaysInterval')) {
                if ($trigger.SelectNodes($xpath, $ns).Count -gt 1) { return $false }
            }
            # Unlike a daily CalendarTrigger, a TimeTrigger never renews a
            # finite repetition window. Persistent tasks must repeat indefinitely.
            if ($trigger.LocalName -ceq 'TimeTrigger' -and $null -ne $trigger.SelectSingleNode('t:Repetition/t:Duration', $ns)) { return $false }
            $interval = $trigger.SelectSingleNode('t:Repetition/t:Interval', $ns)
            $days = $trigger.SelectSingleNode('t:ScheduleByDay/t:DaysInterval', $ns)
            if ($null -ne $days -and $trigger.LocalName -cne 'CalendarTrigger') { return $false }
            $dayCount = 0
            if ($null -ne $days -and (-not [int]::TryParse($days.InnerText, [ref]$dayCount) -or $dayCount -lt 1 -or $dayCount -gt 365)) { return $false }
            $span = $null
            if ($null -ne $interval) {
                $span = [System.Xml.XmlConvert]::ToTimeSpan($interval.InnerText)
                if ($span.TotalMinutes -lt 1 -or $span.TotalDays -gt 365) { return $false }
            }
            if ($isUpdate) {
                if ($trigger.LocalName -ceq 'TimeTrigger' -and $null -ne $span -and $span.TotalHours -eq 1) { $periodic = $true }
            }
            elseif ($ExpectedScanHours -ge 24) {
                # schtasks /SC DAILY /MO min(floor(hours / 24), 365).
                # A repeated intra-day trigger is not this schedule.
                $expectedDays = [Math]::Min([Math]::Floor($ExpectedScanHours / 24.0), 365)
                $periodic = ($trigger.LocalName -ceq 'CalendarTrigger' -and $null -eq $interval -and $dayCount -eq $expectedDays)
            }
            elseif ($ExpectedScanHours -gt 0) {
                # schtasks represents HOURLY through a TimeTrigger or a daily
                # CalendarTrigger with repetition. It must not skip whole days.
                $periodic = ($null -ne $span -and $span.TotalHours -eq $ExpectedScanHours -and ($null -eq $days -or $dayCount -eq 1))
            }
            else {
                # Structural validation for fixtures. Production observation
                # supplies the effective configured interval explicitly.
                $periodic = ($null -ne $span -or $dayCount -gt 0)
            }
        }
        if ($isUpdate) {
            $start = $doc.SelectSingleNode('/t:Task/t:Settings/t:StartWhenAvailable', $ns)
            return ($periodic -and $boot -and $null -ne $start -and $start.InnerText -in @('true','1'))
        }
        return $periodic
    } catch { return $false }
    finally { if ($null -ne $reader) { $reader.Dispose() } }
}

function ConvertFrom-DmgJsonObject {
    param([string]$Json)
        if ($Json.Length -gt 1048576 -or -not $Json.TrimStart().StartsWith('{')) { throw 'invalid_json_object' }
        # PS7 accepts JSON comments/trailing commas that Go's decoder rejects.
        # Reject these outside strings so validation agrees on PS5.1 and PS7.
        $depth = 0; $lastStringEnd = -1
        $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        for ($i = 0; $i -lt $Json.Length; $i++) {
            if ($Json[$i] -eq '"') {
                $start = $i
                $i++
                while ($i -lt $Json.Length) {
                    if ($Json[$i] -eq '\') { $i += 2; continue }
                    if ($Json[$i] -eq '"') { break }
                    $i++
                }
                if ($i -ge $Json.Length) { throw 'invalid_json_object' }
                $lastStringEnd = $i
                $next = $i + 1
                while ($next -lt $Json.Length -and [char]::IsWhiteSpace($Json[$next])) { $next++ }
                if ($depth -eq 1 -and $next -lt $Json.Length -and $Json[$next] -eq ':') {
                    $token = $Json.Substring($start, $i - $start + 1)
                    $key = ConvertFrom-Json -InputObject ('{"key":' + $token + '}') -ErrorAction Stop
                    if (-not $seen.Add([string]$key.key)) { throw 'invalid_json_object' }
                }
                continue
            }
            if ($Json[$i] -eq '/' -or $Json[$i] -eq "'") { throw 'invalid_json_object' }
            if ($Json[$i] -eq ':') {
                $previous = $i - 1
                while ($previous -ge 0 -and [char]::IsWhiteSpace($Json[$previous])) { $previous-- }
                if ($previous -ne $lastStringEnd) { throw 'invalid_json_object' }
            }
            if ($Json[$i] -eq '{' -or $Json[$i] -eq '[') { $depth++ }
            elseif ($Json[$i] -eq '}' -or $Json[$i] -eq ']') { $depth-- }
            if ($Json[$i] -eq ',') {
                $next = $i + 1
                while ($next -lt $Json.Length -and [char]::IsWhiteSpace($Json[$next])) { $next++ }
                if ($next -lt $Json.Length -and ($Json[$next] -eq '}' -or $Json[$next] -eq ']')) { throw 'invalid_json_object' }
            }
        }
        $value = ConvertFrom-Json -InputObject $Json -ErrorAction Stop
        if ($value -isnot [PSCustomObject]) { throw 'invalid_json_object' }
        return $value
}

function Test-DmgStatePointer {
    # Match the bootstrap's frozen LoadPointers contract. Other state fields
    # may evolve; a newer integral schema remains readable, but schema zero,
    # a non-integer schema or a malformed current version forces fallback.
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Json)
    try {
        $value = ConvertFrom-DmgJsonObject -Json $Json
        $names = @($value.PSObject.Properties | ForEach-Object { $_.Name })
        if ($names -cnotcontains 'schema' -or $names -cnotcontains 'current') { return $false }
        $schema = Get-DmgObjectValue $value 'schema'
        if (($schema -isnot [int] -and $schema -isnot [long]) -or $schema -lt 1) { return $false }
        $current = Get-DmgObjectValue $value 'current'
        if ($current -isnot [string] -or $current -cnotmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') { return $false }
        foreach ($part in $current.Split('.')) {
            $component = [uint32]0
            if (-not [uint32]::TryParse($part, [ref]$component)) { return $false }
        }
        return $true
    } catch { return $false }
}

function Test-DmgProtectedPath {
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

function Test-DmgInteractiveAccessRules {
    # This conservative profile certifies broad interactive access, not arbitrary
    # domain ACL policy. Any applicable deny of required rights fails closed.
    param([array]$Rules, [long]$RequiredMask = 1)
    if ($null -eq $Rules -or $RequiredMask -notin @(1,32,33)) { return $false }
    $readers = @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4')
    $allowed = 0L
    foreach ($rule in $Rules) {
        $sid = Get-DmgObjectValue $rule 'Sid'
        $rights = Get-DmgObjectValue $rule 'Rights'
        $allow = Get-DmgObjectValue $rule 'Allow'
        $inheritOnly = Get-DmgObjectValue $rule 'InheritOnly'
        if ($sid -isnot [string] -or ($rights -isnot [int] -and $rights -isnot [long]) -or $allow -isnot [bool] -or $inheritOnly -isnot [bool]) { return $false }
        if ($inheritOnly) { continue }
        if (-not $allow -and ($rights -band $RequiredMask) -ne 0) { return $false }
        if ($allow -and $readers -contains $sid) { $allowed = $allowed -bor $rights }
    }
    return (($allowed -band $RequiredMask) -eq $RequiredMask)
}

function Test-DmgInteractiveRead {
    param([string]$Path, [switch]$Execute)
    try {
        $required = 1L; if ($Execute) { $required = 33L }
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        while ($null -ne $item) {
            $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
            $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
                [pscustomobject]@{
                    Sid=$_.IdentityReference.Value; Rights=[long]$_.FileSystemRights
                    Allow=($_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
                    InheritOnly=(($_.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
                }
            })
            if (-not (Test-DmgInteractiveAccessRules -Rules $rules -RequiredMask $required)) { return $false }
            $parent = [IO.Directory]::GetParent($item.FullName)
            if ($null -eq $parent) { break }
            $item = Get-Item -LiteralPath $parent.FullName -Force -ErrorAction Stop
            $required = 32L
        }
        return $true
    } catch { return $false }
}

function Test-DmgPublisherSignature {
    param([string]$Path, [string]$ExpectedPublisherSubject)
    try {
        if ([string]::IsNullOrWhiteSpace($ExpectedPublisherSubject)) { return $false }
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return ($signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate -and
            $signature.SignerCertificate.Subject -ceq $ExpectedPublisherSubject -and
            $null -ne $signature.TimeStamperCertificate)
    } catch { return $false }
}

function Invoke-DmgReadOnlyProcess {
    # Only diagnostic child processes use this helper. Never use its kill-on-
    # timeout behavior for msiexec: installation timeout is an uncertain state.
    param([string]$FilePath, [string]$Arguments, [int]$TimeoutSeconds = 30)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $FilePath; $start.Arguments = $Arguments
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true; $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'diagnostic_start_failed' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            throw 'diagnostic_timeout'
        }
        # Child output is never logged here; caller parses the expected JSON.
        $out = $stdout.GetAwaiter().GetResult()
        $null = $stderr.GetAwaiter().GetResult()
        if ($out.Length -gt 65536) { throw 'diagnostic_output_too_large' }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $out }
    } finally { $process.Dispose() }
}

function Get-DmgMsiMetadata {
    # Windows Installer automation reads a database without installing it or
    # triggering the repair side effects of Win32_Product discovery.
    param([string]$Path)
    $installer = $null; $database = $null; $summary = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.OpenDatabase($Path, 0)
        $properties = @{}
        foreach ($name in @('ProductName','Manufacturer','ProductVersion','ProductCode','UpgradeCode','ALLUSERS')) {
            $view = $null; $record = $null
            try {
                $view = $database.OpenView(('SELECT `Value` FROM `Property` WHERE `Property` = ''{0}''' -f $name))
                $null = $view.Execute(); $record = $view.Fetch()
                if ($null -ne $record) { $properties[$name] = $record.StringData(1) }
            } finally {
                if ($null -ne $record) { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($record) }
                if ($null -ne $view) { $null = $view.Close(); $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($view) }
            }
        }
        $summary = $database.SummaryInformation(0)
        if ($properties['ProductName'] -cne 'StepSecurity Dev Machine Guard' -or $properties['Manufacturer'] -cne 'StepSecurity' -or $properties['UpgradeCode'].Trim('{}') -ine '65AE0FC0-2070-4F40-B0CA-413637F94121' -or $properties['ALLUSERS'] -cne '1' -or $summary.Property(7) -notmatch '^x64;') { throw 'unsupported_package' }
        if ($properties['ProductVersion'] -notmatch '^\d+\.\d+\.\d+$' -or $properties['ProductCode'] -notmatch '^\{[0-9A-Fa-f-]{36}\}$') { throw 'invalid_package_metadata' }
        return [pscustomobject]@{ ProductVersion = $properties['ProductVersion']; ProductCode = $properties['ProductCode'] }
    } finally {
        foreach ($obj in @($summary,$database,$installer)) { if ($null -ne $obj) { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($obj) } }
    }
}

function Get-DmgInstalledProduct {
    $installer = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $arm = @($installer.RelatedProducts('{99C4A108-6A71-4006-8AA7-F3D14DA045A9}'))
        if ($arm.Count -gt 0) { throw 'unsupported_installed_architecture' }
        $codes = @($installer.RelatedProducts('{65AE0FC0-2070-4F40-B0CA-413637F94121}'))
        if ($codes.Count -gt 1) { throw 'ambiguous_products' }
        if ($codes.Count -eq 0) { return $null }
        $code = [string]$codes[0]
        # INSTALLSTATE_DEFAULT = 5: reject advertised/partial registrations.
        if ($installer.ProductState($code) -ne 5) { throw 'incomplete_product_registration' }
        return [pscustomobject]@{ ProductCode = $code; ProductVersion = $installer.ProductInfo($code, 'VersionString') }
    } finally { if ($null -ne $installer) { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($installer) } }
}

function Read-DmgBoundedJson {
    param([string]$Path, [long]$MaximumBytes = 1048576)
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.PSIsContainer -or $file.Length -gt $MaximumBytes) { throw 'invalid_json_file' }
    return (ConvertFrom-DmgJsonObject -Json ([IO.File]::ReadAllText($file.FullName)))
}

function Get-DmgInstalledObservation {
    <#
    .SYNOPSIS
    Observe an already-trusted machine installation; no MSI mutation.
    .DESCRIPTION
    PackageTrust is supplied only by the caller after external bundle signature
    verification. This is an internal seam, not a public trust-bypass option.
    Wrap the whole native observer in a bounded worker process: Windows COM/ACL
    calls have no cancellation API. Never expose Configuration in result JSON.
    #>
    param([bool]$PackageTrust, [hashtable]$DesiredConfig, [string]$ExpectedPublisherSubject)
    $checks = [ordered]@{ Context=$false; PackageTrust=($PackageTrust -and -not [string]::IsNullOrWhiteSpace($ExpectedPublisherSubject)); Discovery=$false }
    $o = [pscustomobject]@{ Installed=$false; ObservationError=$false; ProductVersion=''; ProductCode=''; RunningVersion=''; Configuration=@{}; Checks=@() }
    try {
        $checks['Context'] = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and [Environment]::Is64BitProcess -and [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') -eq 'AMD64' -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
        if (-not $checks['Context'] -or -not $checks['PackageTrust']) { return $o }
        $product = Get-DmgInstalledProduct
        $root = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'StepSecurity'
        if ($null -eq $product) {
            # Files without product registration are uncertain/legacy, not a
            # clean machine on which it is safe to assume a fresh install.
            if ((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath 'C:\ProgramData\StepSecurity\config.json')) { throw 'unregistered_installation' }
            $checks['Discovery'] = $true
            return $o
        }
        $o.Installed = $true; $o.ProductVersion = $product.ProductVersion; $o.ProductCode = $product.ProductCode
        $checks['Discovery'] = $true
        foreach ($name in @('Layout','RuntimeIntegrity','SelfCheck','VersionConsistency','ScanTask','LogonTask','UpdateTask','ConfigurationAccess')) { $checks[$name] = $false }
        # v1 observes the MSI default layout only. Custom roots fail closed.
        $bootstrap = Join-Path $root 'stepsecurity-dev-machine-guard-bootstrap.exe'
        $configPath = 'C:\ProgramData\StepSecurity\config.json'
        $checks['Layout'] = (Test-DmgProtectedPath $root) -and (Test-DmgProtectedPath $bootstrap) -and (Test-DmgInteractiveRead $bootstrap -Execute)
        $checks['ConfigurationAccess'] = (Test-DmgProtectedPath $configPath) -and (Test-DmgInteractiveRead $configPath)
        if (-not $checks['Layout'] -or -not $checks['ConfigurationAccess']) { return $o }
        if (-not (Test-DmgPublisherSignature -Path $bootstrap -ExpectedPublisherSubject $ExpectedPublisherSubject)) { return $o }
        $stored = Read-DmgBoundedJson $configPath
        foreach ($p in $stored.PSObject.Properties) { $o.Configuration[$p.Name] = $p.Value }
        # Config/environment precedence must not silently route scans elsewhere.
        foreach ($name in @('STEPSEC_DEVICE_ID','USER_EMAIL','DEVELOPER_EMAIL','STEPSEC_DEVELOPER_EMAIL')) {
            if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, 'Machine')) -or -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name, 'Process'))) { $checks['ConfigurationAccess'] = $false }
        }
        $statePath = Join-Path $root 'state\state.json'
        if (-not (Test-DmgProtectedPath $statePath) -or -not (Test-DmgInteractiveRead $statePath)) { return $o }
        $state = Read-DmgBoundedJson $statePath
        if (-not (Test-DmgStatePointer -Json ([IO.File]::ReadAllText($statePath)))) { return $o }
        $current = Get-DmgObjectValue $state 'current'
        if ($current -isnot [string] -or $current -notmatch '^\d+\.\d+\.\d+$') { return $o }
        $o.RunningVersion = $current
        $versionDir = Join-Path $root ('versions\' + $current)
        if (-not (Test-DmgProtectedPath $versionDir)) { return $o }
        $manifestPath = Join-Path $versionDir 'manifest.json'
        if (-not (Test-DmgProtectedPath $manifestPath)) { return $o }
        $manifest = Read-DmgBoundedJson $manifestPath 65536
        $manifestSchema = Get-DmgObjectValue $manifest 'schema'
        if (($manifestSchema -isnot [int] -and $manifestSchema -isnot [long]) -or $manifestSchema -ne 1 -or (Get-DmgObjectValue $manifest 'version') -cne $current) { return $o }
        $hashes = Get-DmgObjectValue $manifest 'files'
        foreach ($name in @('stepsecurity-dev-machine-guard.exe','stepsecurity-dev-machine-guard-task.exe','dmg-linux')) {
            $path = Join-Path $versionDir $name
            $hash = Get-DmgObjectValue $hashes $name
            if ($null -eq $hashes -or @($hashes.PSObject.Properties | ForEach-Object { $_.Name }) -cnotcontains $name) { return $o }
            if ($hash -isnot [string] -or $hash -notmatch '^[0-9a-f]{64}$' -or -not (Test-DmgProtectedPath $path) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -ine $hash) { return $o }
        }
        foreach ($name in @('stepsecurity-dev-machine-guard.exe','stepsecurity-dev-machine-guard-task.exe')) {
            if (-not (Test-DmgInteractiveRead (Join-Path $versionDir $name) -Execute) -or -not (Test-DmgPublisherSignature -Path (Join-Path $versionDir $name) -ExpectedPublisherSubject $ExpectedPublisherSubject)) { return $o }
        }
        $checks['RuntimeIntegrity'] = $true
        $registry = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\StepSecurity' -ErrorAction Stop
        $checks['VersionConsistency'] = ((Get-DmgObjectValue $registry 'AgentVersion') -ceq $o.ProductVersion -and (Get-DmgObjectValue $registry 'RunningVersion') -ceq $current -and [version]$current -ge [version]$o.ProductVersion)
        $diag = Invoke-DmgReadOnlyProcess -FilePath (Join-Path $versionDir 'stepsecurity-dev-machine-guard.exe') -Arguments 'self-check'
        $perUser = $false
        if ($DesiredConfig.ContainsKey('device_id')) { $perUser = ([string]$DesiredConfig['device_id']).ToLowerInvariant().Contains('{user}') }
        $checks['SelfCheck'] = ($diag.ExitCode -eq 0 -and (Test-DmgSelfCheck -Json $diag.Output -ExpectedVersion $current -AllowPerUserIdentity $perUser))
        # A runtime version switch during observation invalidates this snapshot.
        $after = Read-DmgBoundedJson $statePath
        if (-not (Test-DmgStatePointer -Json ([IO.File]::ReadAllText($statePath))) -or (Get-DmgObjectValue $after 'current') -cne $current) { $checks['VersionConsistency'] = $false }
        $scheduler = $null; $folder = $null
        try {
            $scheduler = New-Object -ComObject Schedule.Service; $null = $scheduler.Connect(); $folder = $scheduler.GetFolder('\')
            foreach ($kind in @('Scan','Logon','Update')) {
                $task = $null
                try {
                    $name = 'StepSecurity Dev Machine Guard'
                    if ($kind -ne 'Scan') { $name += ' (' + $kind + ')' }
                    $task = $folder.GetTask($name)
                    $hours = 4
                    if ($DesiredConfig.ContainsKey('scan_frequency_hours') -and $DesiredConfig['scan_frequency_hours'] -ne '') { $hours = [int]$DesiredConfig['scan_frequency_hours'] }
                    $checks[$kind + 'Task'] = ([bool]$task.Enabled -and (Test-DmgTaskXml -Xml $task.Xml -Kind $kind -BootstrapPath $bootstrap -ExpectedScanHours $hours -MaxExecutionDuration ([string]$DesiredConfig['max_execution_duration']) -EnvironmentMaxExecutionDuration ([Environment]::GetEnvironmentVariable('STEPSEC_MAX_EXECUTION_DURATION'))))
                } catch { $checks[$kind + 'Task'] = $false }
                finally { if ($null -ne $task) { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($task) } }
            }
        } finally {
            foreach ($obj in @($folder,$scheduler)) { if ($null -ne $obj) { $null = [Runtime.InteropServices.Marshal]::ReleaseComObject($obj) } }
        }
        return $o
    } catch { $o.ObservationError = $true; return $o }
    finally { $o.Checks = @($checks.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Name=$_.Key; Passed=[bool]$_.Value } }) }
}

Export-ModuleMember -Function Test-DmgInteractiveAccessRules, Test-DmgStatePointer, Test-DmgSelfCheck, Test-DmgTaskXml, Test-DmgProtectedPath, Get-DmgMsiMetadata, Get-DmgInstalledObservation
