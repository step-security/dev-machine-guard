@echo off
setlocal

REM Locate the MSI shipped inside this .intunewin payload. The MSI filename
REM carries the version (e.g. stepsecurity-dev-machine-guard-1.11.6-x64.msi)
REM so SCCM and manual-upgrade flows can distinguish releases by filename.
REM The wildcard pattern lets this wrapper stay version-agnostic.
set "MSI="
for %%f in ("%~dp0stepsecurity-dev-machine-guard-*.msi") do set "MSI=%%f"
if not defined MSI (
    echo ERROR: no stepsecurity-dev-machine-guard MSI found in %~dp0
    exit /b 1
)

set "LOG_DIR=%ProgramData%\StepSecurity"
set "LOG=%LOG_DIR%\install.log"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM /norestart: never let a quiet install reboot a developer machine; a
REM reboot-required result is returned as 3010 for Intune to handle.
REM Forward all args (%*) so MSI public properties like APIKEY, CUSTOMERID,
REM APIENDPOINT, SCANFREQUENCY, AUTOUPDATE pass through from Intune's install
REM command (AUTOUPDATE=0 opts the device out of self-update, AUTOUPDATE=1 back in).
msiexec /i "%MSI%" /qn /norestart /l*v "%LOG%" %*
exit /b %ERRORLEVEL%
