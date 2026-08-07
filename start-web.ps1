$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

python -c "import flask, requests, socks" 2>$null
if ($LASTEXITCODE -ne 0) {
    python -m pip install -r requirements.txt
}

python scripts/web_app.py
