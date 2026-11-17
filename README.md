# 网络工具

Windows 桌面网络工具箱（作者：Lorenzo）。在本地打开独立窗口，内置 Ping、traceroute、端口扫描、HTTP 探测、DNS、测速、系统体检、网卡叠加、SSH、服务器信息提取等 47 项功能。

当前版本：**1.2.0**。

## 1.2.0 主要变化

- **最小化运行默认开启**：最小化时隐藏到系统托盘，可在右上角「设置」中关闭。
- **关闭窗口默认留在后台**：已去掉「保留后台运行」开关。关闭窗口一定隐藏到托盘并保持运行；只有托盘菜单「退出」，或「设置 → 退出程序」，才会彻底结束进程。即使读到旧版 `settings.json`，也会按这个行为执行。
- **开机自启**：写入当前用户的开机启动项（默认关闭）。若已开启「最小化运行」，登录 Windows 后会先进入托盘。
- **网页在软件内打开**：需要访问的外部网页（例如「三网拨测」打开阿里云 boce.aliyun.com）会在软件里再开一个窗口，不再跳到 Edge / 系统浏览器。关闭这个子窗口不影响主程序。主窗口始终是本机界面。
- **已删除「分享软件」**：原先置灰的手机端功能已去掉。
- **网卡叠加**（进阶工具）：把每条新的 TCP 连接分配到已选网卡（源地址绑定 + Windows `IP_UNICAST_IF`）。启动后在本机提供 HTTP 和 SOCKS5 代理，可选接管当前用户的 Windows 系统代理（无需管理员）；停止或退出时会恢复原先设置。这是连接级负载分配，不是拆单条 TCP，也不是 L2 bonding，不能让单连接测速变成多条网络之和。同一路由器下的有线 + Wi-Fi 仍然共享出口带宽。只有走系统代理或手动填写本地代理的应用会分流，可用浏览器、IDM、Steam 等测试。
- **服务器信息提取**：把告警或 CMDB 原文解析成主机名、物理机 SN、管理 IP、BMC IP、型号、机房、故障和区域，并生成「【合营云】{区域}Server业务{主机名}硬件故障」标题和七行信息模板，支持一键复制。请粘贴或点「读取剪贴板」；没有「从当前浏览器页提取」。若 WebView 读不了剪贴板，在原文框按 Ctrl+V 即可自动解析。
- **SSH**：软件内终端。可保存、编辑、删除常用主机（备注名、地址、端口、用户名）。名单只存在 `%LOCALAPPDATA%\网络工具\config\`，不会进 Git。密码默认不保存；若勾选「记住密码」（默认关闭），会用当前 Windows 用户的 DPAPI 加密后另存，公用电脑请勿勾选。私钥只引用你选择的本机路径，不会把密钥内容写入配置。
- **其它新工具**：路由表、ARP 表、网卡实时流量、NAT 类型检测。
- 单文件 exe、配置不写在 exe 旁边，这些行为与 1.1 相同。

## 运行时文件位置

配置、日志、锁文件一律放在：

`%LOCALAPPDATA%\网络工具\`

例如：

- `settings.json` — 最小化到托盘 / 开机自启等偏好
- `config/ai.json` — AI 接口与密钥（仅本机）
- `config/ssh_hosts.json` — SSH 常用主机（密码若选择记住则加密存放）
- `logs/app.log` — 运行日志（超过 5 MB 会轮转）
- `reports\` — 「导出配置包」生成的诊断文本
- `url.txt` / `pid.txt` / `app.lock` — 单实例与运行标记
- `mux_proxy_backup.json` — 网卡叠加若异常退出，用来恢复系统代理

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

在 [Releases](https://github.com/cnsunsz/wangluo-gongju/releases) 下载最新的 `WangLuoGongJu-v1.2.0.exe`（可改名为「网络工具.exe」），双击即可使用。Windows 11 一般已自带 WebView2；若窗口无法打开，请先安装 [Microsoft Edge WebView2](https://developer.microsoft.com/microsoft-edge/webview2/)。

关闭窗口会隐藏到托盘并保持运行。需要彻底退出时，请用托盘图标右键「退出」，或打开窗口后到「设置」里点「退出程序」。

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

「网卡叠加」是连接级多网卡聚合的独立实现，不是 HypoMux，也未使用其源码。
