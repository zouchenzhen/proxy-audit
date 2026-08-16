param(
    [switch]$NoOpen,
    [switch]$SkipCoreDownload,
    [ValidateRange(1, 65535)]
    [int]$Port = 8765
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host '[Proxy Audit] Creating an isolated Python environment...' -ForegroundColor Cyan
    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        & $pyLauncher.Source -3 -m venv (Join-Path $projectRoot '.venv')
    } else {
        $python = Get-Command python -ErrorAction SilentlyContinue
        if (-not $python) {
            throw 'Python 3 was not found. Install Python 3.10+ and add it to PATH.'
        }
        & $python.Source -m venv (Join-Path $projectRoot '.venv')
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython)) {
        throw 'Failed to create .venv. Verify that Python 3.10+ and the venv module are installed.'
    }
}

& $venvPython -c "import flask, requests, socks" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host '[Proxy Audit] Installing Python dependencies...' -ForegroundColor Cyan
    & $venvPython -m pip install -r (Join-Path $projectRoot 'requirements.txt')
    if ($LASTEXITCODE -ne 0) { throw 'Failed to install Python dependencies. Check the network connection and retry.' }
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
    Invoke-WebRequest -UseBasicParsing -Uri "https://github.com/SagerNet/sing-box/releases/download/v$version/sing-box-$version-windows-amd64.zip" -OutFile $archive
    $actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($actualSha256 -ne $expectedSha256) {
        throw "sing-box checksum verification failed. Actual SHA256: $actualSha256"
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $extractRoot -Force
    $downloadedBinary = Get-ChildItem -LiteralPath $extractRoot -Recurse -Filter 'sing-box.exe' -File | Select-Object -First 1
    if (-not $downloadedBinary) {
        throw 'sing-box.exe was not found in the downloaded archive.'
    }
    Copy-Item -LiteralPath $downloadedBinary.FullName -Destination $singBox -Force
}

$webArguments = @('scripts/web_app.py', '--port', $Port)
if ($NoOpen) { $webArguments += '--no-open' }
Write-Host "[Proxy Audit] Starting local panel: http://127.0.0.1:$Port" -ForegroundColor Green
& $venvPython @webArguments
