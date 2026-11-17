# 在 Windows 上把「网络工具」打成单个 exe（无控制台、无 _internal、无 data 目录）
# 用法：在项目根目录执行  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$py = $null
foreach ($c in @("py -3.13", "py -3", "python")) {
  try {
    $ver = Invoke-Expression "$c -c `"import sys; print(sys.version)`"" 2>$null
    if ($LASTEXITCODE -eq 0 -and $ver) { $py = $c; break }
  } catch {}
}
if (-not $py) { throw "未找到 Python 3，请先安装 Python 3.13 并勾选 Add to PATH。" }

Write-Host "使用解释器: $py"
if (-not (Test-Path .venv)) {
  Write-Host "创建虚拟环境 .venv ..."
  Invoke-Expression "$py -m venv .venv"
}
$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $venvPy -m pip install -U pip
& $venvPy -m pip install -r requirements.txt pyinstaller

$addData = @("--add-data", "web;web", "--add-data", "icons;icons")
$addBin = @()
if (Test-Path "bin\iperf3.exe") {
  $addBin += @("--add-binary", "bin\iperf3.exe;bin")
  if (Test-Path "bin\cygwin1.dll") {
    $addBin += @("--add-binary", "bin\cygwin1.dll;bin")
  }
  Write-Host "已包含 bin\iperf3.exe"
} else {
  Write-Host "未找到 bin\iperf3.exe，将不内置 iperf3（可事后放到 exe 同目录或 PATH）"
}

$args = @(
  "--noconfirm", "--clean", "--onefile", "--windowed",
  "--name", "网络工具",
  "--icon", "icons\app.ico",
  "--version-file", "version_info.txt",
  "--hidden-import", "webview",
  "--hidden-import", "pystray",
  "--hidden-import", "PIL",
  "--hidden-import", "dns",
  "--hidden-import", "qrcode",
  "--hidden-import", "paramiko",
  "--hidden-import", "cryptography",
  "--hidden-import", "core.pktcap",
  "--hidden-import", "core.pktcap.dissect",
  "--hidden-import", "core.pktcap.pcapfile",
  "--hidden-import", "core.pktcap.libpcap",
  "--hidden-import", "core.pktcap.session",
  "--hidden-import", "core.pktcap.analysis",
  "--collect-all", "webview",
  "--collect-all", "paramiko",
  "--collect-all", "cryptography"
) + $addData + $addBin + @("app.py")

Write-Host "开始打包..."
& $venvPy -m PyInstaller @args
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 失败" }

$exe = Join-Path $PSScriptRoot "dist\网络工具.exe"
if (Test-Path $exe) {
  $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
  Write-Host "完成：$exe  ($size MB)"
  Write-Host "这是单个 exe，运行时不会在旁边创建 data 目录；配置在 %LOCALAPPDATA%\网络工具\"
} else {
  throw "未生成 exe"
}
