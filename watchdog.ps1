# AutoVuln 守护脚本：每 30 秒检查后端 8000 与靶场 9090，掉线自动拉起
# 用法: powershell -ExecutionPolicy Bypass -File watchdog.ps1   （保持窗口开着）
$ErrorActionPreference = "SilentlyContinue"
$backendDir = Join-Path $PSScriptRoot "backend"

Write-Host "AutoVuln 守护运行中（Ctrl+C 退出），每 30 秒检查一次..." -ForegroundColor Cyan

while ($true) {
    # 后端 8000
    $b = Get-NetTCPConnection -LocalPort 8000 -State Listen
    if (-not $b) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 后端 8000 掉线，正在重启..." -ForegroundColor Yellow
        Start-Process python -ArgumentList "-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8000" -WorkingDirectory $backendDir -WindowStyle Hidden
    }
    # 靶场 9090
    $t = Get-NetTCPConnection -LocalPort 9090 -State Listen
    if (-not $t) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] 靶场 9090 掉线，正在重启..." -ForegroundColor Yellow
        Start-Process python -ArgumentList "demo_vuln_app.py" -WorkingDirectory $PSScriptRoot -WindowStyle Hidden
    }
    Start-Sleep -Seconds 30
}
