@echo off
chcp 65001 >nul
title AutoVuln 一键启动
cd /d "%~dp0"

where python >nul 2>nul || (echo [错误] 未找到 python，请先安装 Python 3.10+ & pause & exit /b 1)

echo ========================================
echo   AutoVuln 一键启动（后端 8000 + 靶场 9090）
echo ========================================

echo [1/3] 检查并启动服务...
powershell -NoProfile -Command "$p = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue; if ($p) { '  后端 8000 已在运行，跳过' } else { Start-Process python -ArgumentList '-m','uvicorn','app.main:app','--host','127.0.0.1','--port','8000' -WorkingDirectory (Join-Path (Get-Location) 'backend') -WindowStyle Hidden; '  后端启动中...' }"
powershell -NoProfile -Command "$p = Get-NetTCPConnection -LocalPort 9090 -State Listen -ErrorAction SilentlyContinue; if ($p) { '  靶场 9090 已在运行，跳过' } else { Start-Process python -ArgumentList 'demo_vuln_app.py' -WorkingDirectory (Get-Location) -WindowStyle Hidden; '  靶场启动中...' }"

echo [2/3] 等待服务就绪...
powershell -NoProfile -Command "$ok=$false; for ($i=0; $i -lt 40; $i++) { try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:8000/' -UseBasicParsing -TimeoutSec 2; if ($r.StatusCode -eq 200) { '  后端就绪 ✓'; $ok=$true; break } } catch {}; Start-Sleep -Seconds 1 }; if (-not $ok) { '  [警告] 后端 40 秒内未就绪，请检查 backend/uvicorn.err.log' }"
powershell -NoProfile -Command "$ok=$false; for ($i=0; $i -lt 40; $i++) { try { $r = Invoke-WebRequest -Uri 'http://127.0.0.1:9090/' -UseBasicParsing -TimeoutSec 2; if ($r.StatusCode -eq 200) { '  靶场就绪 ✓'; $ok=$true; break } } catch {}; Start-Sleep -Seconds 1 }; if (-not $ok) { '  [警告] 靶场 40 秒内未就绪' }"

echo [3/3] 打开平台...
start "" "http://127.0.0.1:8000"
echo.
echo 完成！平台: http://127.0.0.1:8000  (API文档: /api/docs)
echo      靶场: http://127.0.0.1:9090
echo 提示: 服务挂掉自动拉起可运行 watchdog.ps1（每 30 秒检查一次）
echo.
pause
