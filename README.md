# 网络工具

Windows 桌面网络工具箱（作者：Lorenzo）。在本地打开独立窗口，内置 Ping、traceroute、端口扫描、HTTP 探测、DNS、测速、系统体检等 40 余项功能。

## 相对旧版的主要变化

- **纯单个 exe**：PyInstaller `--onefile --windowed`，没有 `_internal` 目录，也不会在 exe 旁边创建 `data` 文件夹。
- **关闭窗口即退出**（默认）：进程、Flask、iperf3/ping/tracert 等子进程会一并结束，不会残留在任务管理器里。
- **可选托盘行为**（需在「设置」中手动打开，默认全关）：
  - **最小化运行**：最小化时隐藏到系统托盘，点击托盘图标恢复窗口。
  - **开机自启**：写入当前用户的开机启动项（默认关闭）。
  - **保留后台运行**：关闭窗口时隐藏到托盘并保持服务，而不是退出。托盘菜单「退出」仍会彻底结束进程。
- 开机自启时，若已开启「最小化运行」或「保留后台运行」，程序会先进入托盘；否则显示主窗口。
- 界面外观已整理：更清晰的顶栏、卡片、按钮与输出区。
- 程序图标改为网络主题（地球 + 节点）。

## 运行时文件位置

配置、日志、锁文件一律放在：

`%LOCALAPPDATA%\网络工具\`

例如：

- `settings.json` — 托盘 / 自启 / 后台运行偏好
- `config/ai.json` — AI 接口与密钥（仅本机）
- `logs/app.log` — 运行日志（超过 5 MB 会轮转）
- `reports\` — 「导出配置包」生成的诊断文本
- `url.txt` / `pid.txt` / `app.lock` — 单实例与运行标记

如果旧版曾在 exe 旁边留下 `data` 目录，首次启动会把其中的 `ai.json` 和日志迁移过来，之后不再依赖那个文件夹。

## 从源码运行

需要 **Windows + Python 3.13**（3.10+ 一般也可）。在项目目录：

```bat
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py
```

会启动本地 `127.0.0.1:8899`（被占用则自动顺延）并用 Edge WebView2 打开窗口。系统需已安装 WebView2（Windows 11 通常自带）。

调试时若只想跑 HTTP 服务、不要窗口，可设置环境变量 `NETMETER_NO_WINDOW=1`。

## 下载

在 [Releases](https://github.com/cnsunsz/wangluo-gongju/releases) 下载最新的 `网络工具.exe`，双击即可使用。Windows 11 一般已自带 WebView2；若窗口无法打开，请先安装 [Microsoft Edge WebView2](https://developer.microsoft.com/microsoft-edge/webview2/)。

关闭窗口默认会完全退出。如需最小化到托盘、开机自启或关闭后保留后台，请在窗口右上角「设置」中打开对应选项。

## 在 Windows 上打包成单个 exe

## 在 Windows 上打包成单个 exe

也可以在本机打包。在项目根目录执行：

```bat
build.bat
```

或：

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

产物：`dist\网络工具.exe`。

可选：把 [iperf3 Windows 版](https://iperf.fr/iperf-download.php) 的 `iperf3.exe` 与 `cygwin1.dll` 放到 `bin\` 后再打包，测速功能即可内置。详见 `bin/README.md`。

## 单实例

若程序已在运行（包括藏在托盘里），再次打开会唤醒已有窗口，而不会再起一个进程。若上次异常退出留下了过期锁，而进程已经不在，会自动忽略并正常启动。

## 许可与说明

作者：Lorenzo。本仓库为对原 PyInstaller 程序的重构与改进，供个人使用与继续开发。
