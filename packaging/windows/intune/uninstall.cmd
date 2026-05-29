@echo off
setlocal

set "MSI="
for %%f in ("%~dp0stepsecurity-dev-machine-guard-*.msi") do set "MSI=%%f"
if not defined MSI (
    echo ERROR: no stepsecurity-dev-machine-guard MSI found in %~dp0
    exit /b 1
)

set "LOG_DIR=%ProgramData%\StepSecurity"
set "LOG=%LOG_DIR%\uninstall.log"
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM msiexec resolves the ProductCode from the MSI file metadata, so the
REM uninstall targets the exact product/version of the shipped MSI.
msiexec /x "%MSI%" /qn /l*v "%LOG%"
exit /b %ERRORLEVEL%
