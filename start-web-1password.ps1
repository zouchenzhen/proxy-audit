param(
    [switch]$NoOpen,
    [switch]$SkipCoreDownload,
    [ValidateRange(1, 65535)]
    [int]$Port = 8765,
    [string]$ProfilePath = (Join-Path $PSScriptRoot '.1password\proxy-audit.env')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$op = Get-Command op -ErrorAction SilentlyContinue
if (-not $op) {
    throw '未找到 1Password CLI（op）。请先安装并启用桌面端 CLI 集成。'
}
if (-not (Test-Path -LiteralPath $ProfilePath)) {
    throw "未找到 1Password Profile：$ProfilePath。请复制 config.1password.example.env 后填写 op:// 引用。"
}

$childArgs = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', (Join-Path $projectRoot 'start-web.ps1'),
    '-Port', $Port
)
if ($NoOpen) { $childArgs += '-NoOpen' }
if ($SkipCoreDownload) { $childArgs += '-SkipCoreDownload' }

& $op.Source run "--env-file=$ProfilePath" -- powershell.exe @childArgs
exit $LASTEXITCODE
