@echo off
chcp 65001 >nul
title AutoVuln 停止服务
cd /d "%~dp0"

echo 停止 AutoVuln 服务（后端 8000 + 靶场 9090）...
powershell -NoProfile -Command "$procs = Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match 'uvicorn|demo_vuln_app' }; if ($procs) { $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force; Write-Output ('  已停止 PID ' + $_.ProcessId) } } else { '  没有正在运行的服务' }"
echo 完成。
pause
