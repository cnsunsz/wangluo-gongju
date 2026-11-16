@echo off
chcp 65001 >nul
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0build.ps1"
if errorlevel 1 (
  echo.
  echo 若 PowerShell 执行策略受限，请以管理员打开 PowerShell 后执行:
  echo   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
  echo 或直接运行:
  echo   powershell -ExecutionPolicy Bypass -File build.ps1
  exit /b 1
)
