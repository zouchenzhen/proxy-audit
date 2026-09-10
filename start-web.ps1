param(
    [switch]$NoOpen,
    [switch]$SkipCoreDownload,
    # Validate in the inner script so invalid ports are included in the log.
    [string]$Port = '8765'
)

$ErrorActionPreference = 'Stop'
$launcherExitCode = 1
$transcriptStarted = $false
$logPath = $env:PROXY_AUDIT_LAUNCHER_LOG

function Start-LauncherTranscript {
    param([string]$Path)
    # PS 5.1 can report a transcript as started even when its target is unusable.
    # Every launch owns a new log. Seed UTF-8 with a BOM so PS 5.1 preserves
    # Chinese paths/messages instead of appending ASCII to CMD's fallback header.
    $probe = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try {
        $preamble = [Text.UTF8Encoding]::new($true).GetPreamble()
        $probe.Write($preamble, 0, $preamble.Length)
    } finally {
        $probe.Dispose()
    }
    Start-Transcript -LiteralPath $Path -Append -ErrorAction Stop | Out-Null
}

try {
    if (-not $logPath) {
        $logName = 'startup-{0}-{1}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID
        try {
            $logDirectory = Join-Path $PSScriptRoot 'logs'
            New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
            $logPath = Join-Path $logDirectory $logName
            Start-LauncherTranscript $logPath
        } catch {
            $logPath = Join-Path ([IO.Path]::GetTempPath()) ('proxy-audit-' + $logName)
            Start-LauncherTranscript $logPath
        }
    } else {
        Start-LauncherTranscript $logPath
    }
    $transcriptStarted = $true
    Write-Host "[Proxy Audit] Startup log: $logPath" -ForegroundColor Cyan
    # Log outside the bootstrap script to catch its parse/binding errors too.
    & (Join-Path $PSScriptRoot 'scripts\start_web_runtime.ps1') -NoOpen:$NoOpen -SkipCoreDownload:$SkipCoreDownload -Port $Port
    $launcherExitCode = 0
} catch {
    Write-Host ''
    Write-Host ('[Proxy Audit] FAILED: ' + $_.Exception.Message) -ForegroundColor Red
    Write-Host $_.InvocationInfo.PositionMessage
    Write-Host $_.ScriptStackTrace
    Write-Host 'Check the error above, fix the problem, then run start-web.cmd again.'
    Write-Host "Startup log: $logPath"
} finally {
    if ($transcriptStarted) {
        Write-Host "[Proxy Audit] Launcher exit code: $launcherExitCode"
        Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    }
}

exit $launcherExitCode
