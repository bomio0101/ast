@echo off
echo 正在检查管理员权限...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo 已获得管理员权限
) else (
    echo 需要管理员权限
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d %~dp0
cd backend
python main.py
pause