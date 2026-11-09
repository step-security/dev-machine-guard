<#
.SYNOPSIS
Installs, upgrades or uninstalls the StepSecurity Dev Machine Guard agent on a
session host from a staged MSI and tenant file, and reports one result line.

.DESCRIPTION
A thin provisioning step for image managers that run a script as SYSTEM when a
host is created (Nerdio scripted actions, Azure Virtual Desktop custom script
extensions, Intune remediation scripts). The MSI and the tenant file
(bootstrap.json from the dashboard's Windows MSI install page) are staged in
the master image, for example under C:\StepSecurity, and nothing runs on the
imaging machine: this script installs on each new host, verifies the result and
ends with exactly one line the image manager can show per host:

    DMG-PROVISION: ok version=<v> tasks=<n>
    DMG-PROVISION: failed <reason>

with exit code 0 or 1. It is idempotent: a host that already runs the staged
version (or a newer one) is verified only; an older install is upgraded in
place. The API key in the tenant file is never written to the log or the
output.

.PARAMETER MsiPath
The MSI to install. Default: the newest stepsecurity-dev-machine-guard-<v>-x64.msi
under C:\StepSecurity, else next to this script.

.PARAMETER BootstrapPath
The tenant file passed as BOOTSTRAPFILE. Default: C:\StepSecurity\bootstrap.json,
else C:\ProgramData\StepSecurity\bootstrap.json.

.PARAMETER LogPath
Where the script appends its log. The MSI's own verbose log is written next to
it. Default: C:\ProgramData\StepSecurity\provision.log.

.PARAMETER Uninstall
Run the MSI uninstall of the installed product instead (msiexec /x by product
code). The MSI's uninstall action retires the device in the dashboard when the
tenant file set retire_on_uninstall. For scale-in hooks.

.EXAMPLE
powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\StepSecurity\Install-DevMachineGuard.ps1

.EXAMPLE
powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\StepSecurity\Install-DevMachineGuard.ps1 -MsiPath C:\StepSecurity\agent.msi -BootstrapPath C:\StepSecurity\bootstrap.json

.EXAMPLE
powershell.exe -ExecutionPolicy Bypass -NoProfile -File C:\StepSecurity\Install-DevMachineGuard.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$MsiPath,
    [string]$BootstrapPath,
    [string]$LogPath = 'C:\ProgramData\StepSecurity\provision.log',
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:ConfigPath = 'C:\ProgramData\StepSecurity\config.json'
$script:ProductName = 'StepSecurity Dev Machine Guard'
$script:MsiPattern = 'stepsecurity-dev-machine-guard-*-x64.msi'

function Write-Log {
    param([string]$Message)
    $line = '{0} {1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $Message
    try {
        $dir = Split-Path -Parent $LogPath
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
        Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    } catch {
        # A log that cannot be written must not fail the provisioning.
    }
    Write-Verbose $line
}

# Finish prints the single result line and exits. Every path ends here.
function Finish {
    param([bool]$Ok, [string]$Detail)
    $line = if ($Ok) { "DMG-PROVISION: ok $Detail" } else { "DMG-PROVISION: failed $Detail" }
    Write-Log $line
    Write-Output $line
    if ($Ok) { exit 0 } else { exit 1 }
}

function Get-InstalledProduct {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "$script:ProductName*" } |
        Select-Object -First 1
}

# Get-MsiVersion reads the version from the release file name
# (stepsecurity-dev-machine-guard-<v>-x64.msi), falling back to the MSI's
# ProductVersion property through Windows Installer.
function Get-MsiVersion {
    param([string]$Path)
    if ([IO.Path]::GetFileName($Path) -match 'stepsecurity-dev-machine-guard-(\d+\.\d+\.\d+)') {
        return $Matches[1]
    }
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @("SELECT Value FROM Property WHERE Property = 'ProductVersion'"))
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        return [string]$record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, 1)
    } catch {
        return ''
    }
}

function ConvertTo-VersionOrZero {
    param([string]$Text)
    try { return [version]$Text } catch { return [version]'0.0.0' }
}

function Resolve-Msi {
    if ($MsiPath) {
        if (-not (Test-Path -LiteralPath $MsiPath)) { Finish $false "msi not found at $MsiPath" }
        return (Resolve-Path -LiteralPath $MsiPath).Path
    }
    $roots = @('C:\StepSecurity', $PSScriptRoot) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    $candidates = foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Filter $script:MsiPattern -File -ErrorAction SilentlyContinue
    }
    $newest = @($candidates) |
        Sort-Object -Property @{ Expression = { ConvertTo-VersionOrZero (Get-MsiVersion $_.FullName) } } -Descending |
        Select-Object -First 1
    if (-not $newest) { Finish $false "no $script:MsiPattern found in C:\StepSecurity or next to the script (pass -MsiPath)" }
    return $newest.FullName
}

function Resolve-Bootstrap {
    foreach ($candidate in @($BootstrapPath, 'C:\StepSecurity\bootstrap.json', 'C:\ProgramData\StepSecurity\bootstrap.json')) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) { return (Resolve-Path -LiteralPath $candidate).Path }
    }
    Finish $false 'bootstrap.json not found (pass -BootstrapPath)'
}

# Invoke-Msiexec runs msiexec and fails the provisioning on any exit code
# other than 0 (done) or 3010 (done, reboot pending). The verbose MSI log is
# the first place to look when it fails.
function Invoke-Msiexec {
    param([string[]]$Arguments, [string]$What, [string]$MsiLog)
    Write-Log "msiexec $($Arguments -join ' ')"
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $Arguments -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
        Finish $false "$What exit code $($process.ExitCode) (see $MsiLog)"
    }
    Write-Log "$What finished with exit code $($process.ExitCode)"
}

function Get-TaskCount {
    @(Get-ScheduledTask -TaskName 'StepSecurity*' -ErrorAction SilentlyContinue).Count
}

$logDir = Split-Path -Parent $LogPath
if (-not $logDir) { $logDir = 'C:\ProgramData\StepSecurity' }

if ($Uninstall) {
    $product = Get-InstalledProduct
    if (-not $product) { Finish $true 'version=none tasks=0 (not installed)' }
    $msiLog = Join-Path $logDir 'uninstall.msi.log'
    Invoke-Msiexec -Arguments @('/x', $product.PSChildName, '/qn', '/norestart', '/l*v', "`"$msiLog`"") -What 'uninstall' -MsiLog $msiLog
    $left = Get-TaskCount
    if ($left -ne 0) { Finish $false "uninstall left $left scheduled task(s)" }
    Finish $true "version=none tasks=0 (uninstalled $($product.DisplayVersion))"
}

$msi = Resolve-Msi
$bootstrap = Resolve-Bootstrap
$target = Get-MsiVersion $msi
$installed = Get-InstalledProduct
$msiLog = Join-Path $logDir 'install.msi.log'
Write-Log "msi=$msi version=$target bootstrap=$bootstrap installed=$(if ($installed) { $installed.DisplayVersion } else { 'none' })"

$upToDate = $installed -and $target -and $installed.DisplayVersion -and
    ((ConvertTo-VersionOrZero $installed.DisplayVersion) -ge (ConvertTo-VersionOrZero $target))
if ($upToDate) {
    Write-Log "version $($installed.DisplayVersion) is already installed; verifying only"
} else {
    Invoke-Msiexec -Arguments @('/i', "`"$msi`"", '/qn', '/norestart', "BOOTSTRAPFILE=`"$bootstrap`"", '/l*v', "`"$msiLog`"") -What 'install' -MsiLog $msiLog
}

# Verify: the three scheduled tasks (periodic scan, scan at logon, update)
# and a config that names the tenant the bootstrap file names. Only the
# tenant id is compared; the key never leaves the files.
$tasks = Get-TaskCount
if ($tasks -lt 3) { Finish $false "expected 3 scheduled tasks, found $tasks (see $msiLog)" }
if (-not (Test-Path -LiteralPath $script:ConfigPath)) { Finish $false "config.json missing at $script:ConfigPath" }
try {
    $config = Get-Content -LiteralPath $script:ConfigPath -Raw | ConvertFrom-Json
    $wanted = Get-Content -LiteralPath $bootstrap -Raw | ConvertFrom-Json
} catch {
    Finish $false "could not parse config.json or the bootstrap file: $($_.Exception.Message)"
}
if ($wanted.customer_id -and ($config.customer_id -ne $wanted.customer_id)) {
    Finish $false "config.json names tenant '$($config.customer_id)' but the bootstrap file names '$($wanted.customer_id)'"
}
$version = (Get-InstalledProduct).DisplayVersion
if (-not $version) { $version = $target }
Finish $true "version=$version tasks=$tasks"
