@echo off
setlocal DisableDelayedExpansion
set "PROXY_AUDIT_LAUNCHER_LOG=%~dp0logs\startup-%RANDOM%-%RANDOM%.log"
if not exist "%~dp0logs\" mkdir "%~dp0logs" >nul 2>&1
>"%PROXY_AUDIT_LAUNCHER_LOG%" echo [Proxy Audit] Windows launcher started.
if not errorlevel 1 goto run
set "PROXY_AUDIT_LAUNCHER_LOG=%TEMP%\proxy-audit-startup-%RANDOM%-%RANDOM%.log"
>"%PROXY_AUDIT_LAUNCHER_LOG%" echo [Proxy Audit] Windows launcher started. Project logs directory is not writable.
if not errorlevel 1 goto run
echo [Proxy Audit] Cannot write a startup log in the project directory or TEMP.
set "launcherExitCode=1"
goto finish

:run
echo [Proxy Audit] Startup log: "%PROXY_AUDIT_LAUNCHER_LOG%"
if not exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" goto no_powershell
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-web.ps1" %*
set "launcherExitCode=%ERRORLEVEL%"
goto record_exit

:no_powershell
echo [Proxy Audit] Windows PowerShell was not found. Repair or enable Windows PowerShell and retry.
>>"%PROXY_AUDIT_LAUNCHER_LOG%" echo [Proxy Audit] Windows PowerShell was not found.
set "launcherExitCode=1"

:record_exit
>>"%PROXY_AUDIT_LAUNCHER_LOG%" echo [Proxy Audit] Launcher exited with code %launcherExitCode%.
if "%launcherExitCode%"=="0" goto finish
echo.
echo [Proxy Audit] Startup or server failure. Exit code: %launcherExitCode%
echo [Proxy Audit] Read the error above. Startup log: "%PROXY_AUDIT_LAUNCHER_LOG%"

:finish
if "%launcherExitCode%"=="0" goto done
if "%PROXY_AUDIT_NO_PAUSE%"=="1" goto done
echo [Proxy Audit] Press any key to close this window.
pause >nul
:done
endlocal & exit /b %launcherExitCode%
