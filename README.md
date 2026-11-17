# 网络工具

桌面网络工具箱（作者：Lorenzo），提供 **Windows** 与 **macOS** 版本。在本地打开独立窗口，内置 Ping、traceroute、端口扫描、HTTP 探测、DNS、测速、系统体检、抓包分析、网卡叠加、SSH、服务器信息提取等功能（Windows 共 48 项；macOS 隐藏仅 Windows 可用的「Windows 诊断」和「WLAN 分析」）。

当前版本：**1.2.6**。

## 1.2.6 主要变化

- **分析结论写得更完整详细**：选中报文后，「报文分析」会列出多条本包结论，每条都写清协议、收发地址、端口含义（例如 4789 为 VXLAN）、载荷和上下文，并完整展开。抓包页改为可上下滚动的长板，本包结论与整次抓包结论分层显示。

## 1.2.5 主要变化

- **选中报文可直接看到分析结论**：打开 pcap 或抓到包后会自动选中第一条可见报文，「报文分析」最上方以卡片列出本包的若干条分析结论（例如三次握手第 2 拍 SYN-ACK、FIN 正在关闭连接、DNS 查询某域名、TLS ClientHello 的 SNI、纯 ACK、RST 中止连接，以及校验和异常、截断、零窗口、可能重传等）。整次抓包结论放在下面，不再挡住本包结论。

## 1.2.4 主要变化

- **抓包页布局**：把原来挤在一起的界面拆开。Npcap 提示改为一行可展开、可关闭的短横幅；工具栏分成「网卡与开始/停止/打开保存」和「过滤 / 上限 / 跟踪流 / 统计 / 深度分析」两行；抓包页隐藏底部通用的「开始 / 停止 / 清空 / 就绪」，避免和工具栏按钮重复。同一页内分为报文列表、报文分析、报文详情、报文字节四块，宽屏时分析与详情左右并排，均可拖动分隔条，默认高度能看清多层字段和多行十六进制。
- **报文分析与离线诊断**：选中一条报文后，「报文分析」用中文说明这条报文在做什么（例如 TCP 握手的 SYN / SYN-ACK / ACK、FIN 关闭、RST、HTTP 请求、DNS 查询或应答、TLS ClientHello 的 SNI），并给出传统规则提示（纯 ACK、零窗口、可能的重传、校验和异常等）。同时对当前打开或抓到的报文（若设置了显示过滤，则针对可见集合）给出若干离线诊断结论，例如握手是否完成、连接是否在关闭、是否出现 RST / 重传、主要协议与 HTTP / DNS / TLS SNI 等可确定的事实。分析由本机规则引擎生成，不调用 AI，也不联网。
- **深度分析（可选）**：抓包页增加「深度分析」，把脱敏后的摘要、统计和离线结论发给已在「AI 设置」中配置的 OpenAI 兼容接口。未配置时会引导去设置。密钥仍只保存在本机 `ai.json`；不会把完整原始报文无限制发送给模型。
- **AI 设置新增预设**：小米 MiMo（默认 `https://api.xiaomimimo.com/v1`，模型 `mimo-v2.6-pro`；Token Plan 需改用控制台中的地址和 `tp-` / `ttp-` 密钥，不要与 `sk-` 混用）和 Grok（默认 `https://api.x.ai/v1`，模型 `grok-4.7`）。保留阿里云百炼、DeepSeek、OpenAI、本地 Ollama 与自定义。切换预设会自动填入地址和模型，API Key 需自行填写，软件不内置任何密钥。

## 1.2.3 主要变化

- **抓包分析**：新增类 Wireshark 的三栏视图（报文列表、逐层 Packet Details、十六进制/ASCII 字节）。点击一条报文可解析 Frame / Ethernet / IPv4 或 IPv6 / TCP、UDP、ICMP / ARP / DNS / HTTP，以及常见 TLS 握手字段（记录类型、版本、SNI；解不出会标明「未解出」）。点选字段会尽量高亮对应字节。支持简单显示过滤、按协议/会话统计、跟踪 TCP 流、打开与保存 `.pcap`（常见 `.pcapng` 也可读；结构过复杂时会提示另存为 pcap）。
- **实时抓包可选**：列出网卡、设置 BPF 过滤（预置 tcp / udp / icmp / dns / http / tls/443 / arp）、开始/停止/清空。默认最多保留 10000 个包，超限可丢弃最旧或停止并提示，避免把进程撑死。流量只在本机分析，不会上传。
- **不内置 Npcap**：Windows 实时抓包需自行安装 [Npcap](https://npcap.com/)（本程序不随包装此组件）。未安装或不具备权限时，界面会说明原因，**仍可打开 pcap 做离线分析**。macOS 实时抓包使用系统 libpcap，若缺少 `/dev/bpf*` 权限会同样提示；打开文件不需要这些权限。明文协议可能含账号、密码或 Cookie，请仅在本机、仅对你有权分析的流量使用。

## 1.2.2 主要变化

- **修复 Windows 无法启动**：v1.2.1 把窗口/托盘图标优先选成了 PNG，pywebview 交给 `System.Drawing.Icon` 后进程会直接退出，没有任何窗口或报错。1.2.2 在 Windows 上只向窗口传入 `.ico`，托盘用 Pillow 把 PNG/ICO 转成 RGBA 图像；图标失败会降级为无图标继续启动，并在 `%LOCALAPPDATA%\网络工具\logs\app.log` 写下完整异常。
- **崩溃后可再次打开**：上次异常退出留下的单实例锁，若进程已死或本地服务无响应，会自动接管，避免再点一次完全没反应。
- **macOS 启动防护**：窗口优先使用打包进去的 `app.icns`，不会把 Windows `.ico` 直接交给 Cocoa。托盘在主界面就绪后再创建，失败只影响菜单栏图标，主窗口和 Dock 仍可使用。

## 1.2.1 主要变化

- **减号最小化到任务栏 / Dock**：点窗口右上角「减号」（macOS 为黄灯）只做普通最小化，窗口留在任务栏或 Dock，再点图标即可恢复。不会隐藏到托盘，也不会从任务栏 / Dock 消失。已去掉「最小化运行」开关。
- **关闭才进后台**：点「关闭」（X / 红灯）仍然隐藏到托盘（Windows）或菜单栏 / 后台（macOS）并保持运行；只有托盘或菜单栏「退出」，或「设置 → 退出程序」，才会彻底结束进程。开机自启会正常显示主窗口。
- **标题栏搜索工具**：在顶部标题栏「设置」左侧增加搜索框，可按工具中文名或常见英文（如 ping、ssh）即时过滤主界面图标。清空后恢复全部；在搜索框按 Enter，若只剩一项则打开该工具，按 Esc 清空。
- **新增 macOS 版**：优先提供 Apple Silicon（arm64）压缩包，并尝试构建 Intel（x64）。SSH、服务器信息提取、搜索栏、关闭进后台等通用能力可用。详见下方「macOS 说明」。

## 1.2.0 主要变化

- **关闭窗口默认留在后台**：已去掉「保留后台运行」开关。关闭窗口一定隐藏到托盘并保持运行；只有托盘菜单「退出」，或「设置 → 退出程序」，才会彻底结束进程。即使读到旧版 `settings.json`，也会按这个行为执行。
- **开机自启**：写入当前用户的开机启动项（默认关闭）。1.2.1 起开机后会显示主窗口（不再因「最小化运行」先进托盘）。macOS 写入 `~/Library/LaunchAgents/`。
- **网页在软件内打开**：需要访问的外部网页（例如「三网拨测」打开阿里云 boce.aliyun.com）会在软件里再开一个窗口，不再跳到系统浏览器。关闭这个子窗口不影响主程序。主窗口始终是本机界面。
- **已删除「分享软件」**：原先置灰的手机端功能已去掉。
- **网卡叠加**（进阶工具）：把每条新的 TCP 连接分配到已选网卡（源地址绑定；Windows 另设 `IP_UNICAST_IF`，macOS 另设 `IP_BOUND_IF`）。启动后在本机提供 HTTP 和 SOCKS5 代理。Windows 上可选择接管当前用户系统代理（无需管理员），停止或退出时会恢复原先设置；macOS 不接管系统代理，请在浏览器或下载器中手动填写本地代理。这是连接级负载分配，不是拆单条 TCP，也不是 L2 bonding，不能让单连接测速变成多条网络之和。同一路由器下的有线 + Wi-Fi 仍然共享出口带宽。
- **服务器信息提取**：把告警或 CMDB 原文解析成主机名、物理机 SN、管理 IP、BMC IP、型号、机房、故障和区域，并生成「【合营云】{区域}Server业务{主机名}硬件故障」标题和七行信息模板，支持一键复制。请粘贴或点「读取剪贴板」。
- **SSH**：软件内终端。可保存、编辑、删除常用主机（备注名、地址、端口、用户名）。名单只存在本机配置目录，不会进 Git。密码默认不保存；若勾选「记住密码」（默认关闭），Windows 用当前用户 DPAPI 加密，macOS / Linux 用本机 Fernet 密钥加密。公用电脑请勿勾选。私钥只引用你选择的本机路径，不会把密钥内容写入配置。
- **其它新工具**：路由表、ARP 表、网卡实时流量、NAT 类型检测。

## 运行时文件位置

配置、日志、锁文件一律放在用户数据目录，不会在程序旁边创建 data 文件夹。

- **Windows**：`%LOCALAPPDATA%\网络工具\`
- **macOS**：`~/Library/Application Support/网络工具/`

例如：

- `settings.json` — 开机自启等偏好
- `config/ai.json` — AI 接口与密钥（仅本机）
- `config/ssh_hosts.json` — SSH 常用主机（密码若选择记住则加密存放）
- `logs/app.log` — 运行日志（超过 5 MB 会轮转）
- `reports/` — 「导出配置包」生成的诊断文本
- `url.txt` / `pid.txt` / `app.lock` — 单实例与运行标记
- `mux_proxy_backup.json` — 网卡叠加若异常退出，用来恢复系统代理（Windows）

如果旧版曾在 exe 旁边留下 `data` 目录，首次启动会把其中的 `ai.json` 和日志迁移过来，之后不再依赖那个文件夹。

## 下载

在 [Releases](https://github.com/cnsunsz/wangluo-gongju/releases) 下载对应系统的包：

- Windows：`WangLuoGongJu-v1.2.6.exe`（可改名为「网络工具.exe」），双击即可使用。Windows 11 一般已自带 WebView2；若窗口无法打开，请先安装 [Microsoft Edge WebView2](https://developer.microsoft.com/microsoft-edge/webview2/)。
- macOS Apple Silicon：`WangLuoGongJu-v1.2.6-macOS-arm64.zip`，解压得到「网络工具.app」。若提供 Intel 包，文件名为 `WangLuoGongJu-v1.2.6-macOS-x64.zip`。

点减号（macOS 为黄灯）会最小化到任务栏 / Dock，点关闭才会隐藏到后台并保持运行。需要彻底退出时，请用托盘或菜单栏图标「退出」，或打开窗口后到「设置」里点「退出程序」。标题栏「搜索工具」可过滤主界面图标。

## macOS 说明

- 安装包未经 Apple 开发者签名与公证。第一次打开时，请按住 Control 点击「网络工具.app」再选「打开」；或到「系统设置 → 隐私与安全性」允许打开。也可以在终端执行：`xattr -dr com.apple.quarantine 网络工具.app`。
- 「Windows 诊断」「WLAN 分析」仅 Windows 提供，macOS 主界面不显示这两项。
- 网卡叠加在 Mac 上可用源地址绑定和 `IP_BOUND_IF`，但不会修改系统代理，需要分流的应用请手动填写软件里显示的本地 HTTP / SOCKS5 地址。
- 开机自启会写入当前用户的 `~/Library/LaunchAgents/com.cnsunsz.wangluogongju.plist`。
- 窗口使用系统 WKWebView（无需 WebView2）。
- 「抓包分析」打开 pcap 不需要额外权限。实时抓包使用系统 libpcap，若提示无法访问 `/dev/bpf*`，请用管理员权限运行，或在「隐私与安全性」中授权。

## 从源码运行

需要 **Python 3.13**（3.10+ 一般也可）。

Windows：

```bat
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python app.py
```

会启动本地 `127.0.0.1:8899`（被占用则自动顺延）并用 Edge WebView2 打开窗口。

macOS：

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

会用 Cocoa / WKWebView 打开窗口。

调试时若只想跑 HTTP 服务、不要窗口，可设置环境变量 `NETMETER_NO_WINDOW=1`。

## 打包

Windows 单文件 exe，在项目根目录执行 `build.bat` 或：

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

产物：`dist\网络工具.exe`。可选把 [iperf3 Windows 版](https://iperf.fr/iperf-download.php) 的 `iperf3.exe` 与 `cygwin1.dll` 放到 `bin\` 后再打包。

macOS 打包（在 macOS 上执行）：

```bash
bash build-macos.sh
```

产物：`dist/网络工具.app` 以及 `dist/WangLuoGongJu-<版本>-macOS-<arm64|x64>.zip`。脚本会尝试用 Homebrew 内置 `iperf3`。

## 单实例

若程序已在运行（包括藏在托盘或后台），再次打开会唤醒已有窗口，而不会再起一个进程。若上次异常退出留下了过期锁，而进程已经不在，会自动忽略并正常启动。

## 许可与说明

作者：Lorenzo。本仓库为对原 PyInstaller 程序的重构与改进，供个人使用与继续开发。

「网卡叠加」是连接级多网卡聚合的独立实现，不是 HypoMux，也未使用其源码。

「抓包分析」是独立实现的报文查看与协议解析，不是 Wireshark / tshark，也不内置或再分发 Npcap。Windows 实时抓包请自行到 https://npcap.com/ 安装 Npcap。
