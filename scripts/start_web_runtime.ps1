param(
    [switch]$NoOpen,
    [switch]$SkipCoreDownload,
    [ValidateRange(1, 65535)]
    [int]$Port = 8765
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot

function Invoke-StartupPython {
    param([string]$Python, [string[]]$Arguments)
    # PS 5.1 turns redirected native stderr into ErrorRecords. Keep diagnostics
    # visible/in the transcript, and let the native exit code decide success.
    $ErrorActionPreference = 'Continue'
    $PSNativeCommandUseErrorActionPreference = $false
    $global:LASTEXITCODE = 1
    & $Python @Arguments 2>&1 | ForEach-Object { Write-Host $_.ToString() }
    return $global:LASTEXITCODE
}

Push-Location -LiteralPath $projectRoot
try {
    foreach ($requiredFile in @('requirements.txt', 'scripts\web_app.py')) {
        if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $requiredFile) -PathType Leaf)) {
            throw "Missing project file: $requiredFile. Extract the entire ZIP into a writable folder before running start-web.cmd."
        }
    }

    # Check early, before downloading or installing anything.
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Server.ExclusiveAddressUse = $true
    try {
        $listener.Start()
    } catch {
        throw "Cannot listen on 127.0.0.1:$Port. The port may be in use or reserved. Close the existing server or run start-web.cmd -Port 8766. Details: $($_.Exception.Message)"
    } finally {
        $listener.Stop()
    }

    $versionProbe = 'import sys; print(sys.version.split()[0]); sys.exit(0 if sys.version_info >= (3, 10) else 1)'
    $venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        $basePython = $null
        $baseArguments = @()
        foreach ($candidate in @('py', 'python', 'python3')) {
            $command = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue
            if (-not $command) { continue }
            $candidateArguments = @()
            if ($candidate -eq 'py') { $candidateArguments += '-3' }
            Write-Host "[Proxy Audit] Checking $candidate for Python 3.10+..."
            $code = Invoke-StartupPython $command.Source ($candidateArguments + @('-c', $versionProbe))
            if ($code -eq 0) {
                $basePython = $command.Source
                $baseArguments = $candidateArguments
                break
            }
        }
        if (-not $basePython) {
            throw 'A working Python 3.10+ was not found. Install Python from https://www.python.org/downloads/windows/ with Add python.exe to PATH enabled, then reopen start-web.cmd.'
        }
        Write-Host '[Proxy Audit] Creating an isolated Python environment...' -ForegroundColor Cyan
        $code = Invoke-StartupPython $basePython ($baseArguments + @('-m', 'venv', (Join-Path $projectRoot '.venv')))
        if ($code -ne 0 -or -not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
            throw 'Failed to create .venv. Check the Python installation, venv module, and folder write permissions; extract the ZIP into a writable folder.'
        }
    }

    $code = Invoke-StartupPython $venvPython @('-c', $versionProbe)
    if ($code -ne 0) {
        throw 'The existing .venv cannot run Python 3.10+. Install Python 3.10+, rename .venv to .venv-backup, then retry.'
    }

    $code = Invoke-StartupPython $venvPython @('-c', 'import flask, requests, socks')
    if ($code -ne 0) {
        Write-Host '[Proxy Audit] Installing Python dependencies...' -ForegroundColor Cyan
        $code = Invoke-StartupPython $venvPython @('-m', 'pip', 'install', '-r', (Join-Path $projectRoot 'requirements.txt'))
        if ($code -ne 0) { throw 'Failed to install Python dependencies. Check the pip error above and your network connection, then retry.' }
        $code = Invoke-StartupPython $venvPython @('-c', 'import flask, requests, socks')
        if ($code -ne 0) { throw 'Python dependencies are still unavailable after pip finished. Check the import error above.' }
    }

    $singBox = Join-Path $projectRoot 'bin\sing-box.exe'
    if (-not $SkipCoreDownload -and -not (Test-Path -LiteralPath $singBox)) {
        $version = '1.13.3'
        $expectedSha256 = '92A5296EE06B59E6E31F682ADB872854AF1BE0176DA6E8A3B147599254F786F5'
        $downloadRoot = Join-Path $projectRoot 'temp\bootstrap\sing-box-1.13.3'
        $archive = Join-Path $downloadRoot 'sing-box.zip'
        $extractRoot = Join-Path $downloadRoot 'extract'
        New-Item -ItemType Directory -Force -Path $downloadRoot, $extractRoot, (Split-Path -Parent $singBox) | Out-Null
        Write-Host '[Proxy Audit] Downloading sing-box from the official release...' -ForegroundColor Cyan
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -UseBasicParsing -TimeoutSec 120 -Uri "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip" -OutFile $archive
        } catch {
            throw "Failed to download sing-box from GitHub. Check your network connection, then retry. Details: $($_.Exception.Message)"
        }
        $actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
        if ($actualSha256 -ne $expectedSha256) {
            throw "sing-box checksum verification failed. Actual SHA256: $actualSha256"
        }
        Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot -Force
        $downloadedBinary = Get-ChildItem -LiteralPath $extractRoot -Recurse -Filter 'sing-box.exe' -File | Select-Object -First 1
        if (-not $downloadedBinary) { throw 'sing-box.exe was not found in the downloaded archive.' }
        Copy-Item -LiteralPath $downloadedBinary.FullName -Destination $singBox -Force
    }

    $webArguments = @('-u', 'scripts/web_app.py', '--port', $Port)
    if ($NoOpen) { $webArguments += '--no-open' }
    Write-Host "[Proxy Audit] Starting local panel: http://127.0.0.1:$Port" -ForegroundColor Green
    $code = Invoke-StartupPython $venvPython $webArguments
    if ($code -ne 0) { throw "The Web server exited with code $code. Check the error above." }
} finally {
    Pop-Location
}
