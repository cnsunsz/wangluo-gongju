"""Windows 系统体检：启动、蓝屏、性能、更新、设备、激活等。"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import nettools
from .net_extra import ntp_offset, wlan_status
from .util import run_cmd

CATEGORIES = (
    ("boot", "启动与开机"),
    ("bsod", "蓝屏与异常重启"),
    ("perf", "性能与卡顿"),
    ("update", "Windows 更新"),
    ("device", "网络 / 外设 / 音频"),
    ("files", "系统文件与权限"),
    ("license", "激活 / 磁盘 / 存储"),
    ("misc", "其他高频问题"),
)

SERVICE_STATES = {
    1: "Stopped", 2: "StartPending", 3: "StopPending", 4: "Running",
    5: "ContinuePending", 6: "PausePending", 7: "Paused",
}
START_TYPES = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}


def _ps(expr, timeout=18):
    try:
        return nettools._ps_data(expr, timeout)
    except Exception:
        return None


def _list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _one(value):
    items = _list(value)
    return items[0] if items else None


def _finding(level, title, detail=""):
    return {"type": "finding", "level": level, "title": title, "detail": detail}


def _size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "—"
    if n >= 1073741824:
        return f"{n / 1073741824:.1f} GB"
    if n >= 1048576:
        return f"{int(n / 1048576)} MB"
    return f"{int(n)} B"


PS_OVERVIEW = (
    "$os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem; "
    "$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; "
    "$p=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
    ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
    "[pscustomobject]@{os=$os.Caption; build=[string]$os.BuildNumber; boot=[string]$os.LastBootUpTime; "
    "uptime=[string]((Get-Date)-$os.LastBootUpTime); totalMB=[math]::Round($cs.TotalPhysicalMemory/1MB); "
    "freeMB=[math]::Round($os.FreePhysicalMemory/1KB); cpu=[string]$cpu.Name; admin=$p; "
    "model=[string]$cs.Model; name=[string]$os.CSName}"
)

PS_BOOT = (
    "$os=Get-CimInstance Win32_OperatingSystem; $cs=Get-CimInstance Win32_ComputerSystem; "
    "$cpu=Get-CimInstance Win32_Processor | Select-Object -First 1; "
    "$fast=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' "
    "-Name HiberbootEnabled -ErrorAction SilentlyContinue; "
    "$st=@(Get-CimInstance Win32_StartupCommand | Select-Object Name,Location,User); "
    "$pd=@(Get-PhysicalDisk -ErrorAction SilentlyContinue | Select-Object FriendlyName,MediaType,HealthStatus,OperationalStatus); "
    "$p=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
    ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); "
    "[pscustomobject]@{os=$os.Caption; build=[string]$os.BuildNumber; boot=[string]$os.LastBootUpTime; "
    "uptime=[string]((Get-Date)-$os.LastBootUpTime); totalMB=[math]::Round($cs.TotalPhysicalMemory/1MB); "
    "freeMB=[math]::Round($os.FreePhysicalMemory/1KB); cpu=[string]$cpu.Name; admin=$p; "
    "model=[string]$cs.Model; name=[string]$os.CSName; fast=[string]$fast.HiberbootEnabled; "
    "startup=@($st); physical=@($pd)}"
)

PS_DISKS = (
    'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | '
    "Select-Object DeviceID,@{n='totalGB';e={[math]::Round($_.Size/1GB,1)}},"
    "@{n='freeGB';e={[math]::Round($_.FreeSpace/1GB,1)}}"
)


def _overview():
    return _one(_ps(PS_OVERVIEW))


def _disks():
    return _list(_ps(PS_DISKS))


def _services(names):
    expr = "Get-Service " + ",".join(names) + " -ErrorAction SilentlyContinue | Select-Object Name,DisplayName,Status,StartType"
    rows = _list(_ps(expr))
    out = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        status, start = r.get("Status"), r.get("StartType")
        if isinstance(status, (int, float)) or (isinstance(status, str) and status.isdigit()):
            status = SERVICE_STATES.get(int(status), status)
        if isinstance(start, (int, float)) or (isinstance(start, str) and str(start).isdigit()):
            start = START_TYPES.get(int(start), start)
        name = r.get("Name")
        if name:
            r = dict(r)
            r["Status"], r["StartType"] = str(status), str(start)
            out[name] = r
    return out


def _pnp_errors():
    return _list(_ps(
        "Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | "
        "Where-Object {$_.Status -eq 'Error' -or $_.Status -eq 'Degraded'} | "
        "Select-Object -First 12 FriendlyName,Class,Status"
    ))


def _events(ids, days=14, extra=""):
    ids = _list(ids)
    expr = (
        "Get-WinEvent -FilterHashtable @{LogName='System'; Id=" + str(ids).replace("'", "") +
        "; StartTime=(Get-Date).AddDays(-" + str(days) + ")}" + extra +
        " -ErrorAction SilentlyContinue | Select-Object -First 8 TimeCreated,Id,ProviderName,"
        "@{n='Msg';e={$m=[string]$_.Message; $m.Substring(0,[Math]::Min(180,$m.Length))}}"
    )
    # Fix: original uses Id=41,1001,6008 in hashtable
    id_list = ",".join(str(i) for i in ids)
    expr = (
        "Get-WinEvent -FilterHashtable @{LogName='System'; Id=" + id_list +
        "; StartTime=(Get-Date).AddDays(-" + str(days) + ")}"
        " -ErrorAction SilentlyContinue | Select-Object -First 8 TimeCreated,Id,ProviderName,"
        "@{n='Msg';e={$m=[string]$_.Message; $m.Substring(0,[Math]::Min(180,$m.Length))}}"
    )
    return _list(_ps(expr, 20))


def _uptime_days(text):
    """Parse PowerShell TimeSpan string like '7.04:12:33.123' or '04:12:33'."""
    text = str(text or "")
    # take last comma-separated chunk if needed
    part = text.split(",")[-1].strip() if "," in text else text.strip()
    days, h, m, sec = 0, 0, 0, 0
    try:
        if "." in part and ":" in part:
            # d.hh:mm:ss
            d, rest = part.split(".", 1)
            if d.isdigit() and ":" in rest:
                days = int(d)
                parts = rest.split(":")
                h, m, sec = int(parts[0]), int(parts[1]), int(float(parts[2])) if len(parts) > 2 else 0
            else:
                parts = part.split(":")
                h, m = int(parts[0]), int(parts[1])
        elif ":" in part:
            parts = part.split(":")
            if len(parts) >= 3:
                h, m, sec = int(parts[0]), int(parts[1]), int(float(parts[2]))
        else:
            return 0
    except (ValueError, IndexError):
        return 0
    return days + h / 24 + m / 1440


def _boot_bundle():
    return _one(_ps(PS_BOOT, 30))


def _check_boot(ctx):
    out = []
    ov = ctx.get("overview") or ctx.get("boot") or {}
    if not ov:
        out.append(_finding("warn", "基础信息获取失败", "PowerShell/CIM 不可用"))
        return out
    import platform
    out.append(_finding(
        "info",
        "系统：" + (ov.get("os") or "Windows") + "（Build " + str(ov.get("build") or "?") + "）",
        "主机 " + str(ov.get("name") or platform.node()) + " · 型号 " + str(ov.get("model") or "—"),
    ))
    b = ov.get("boot") or ""
    days = _uptime_days(ov.get("uptime") or "")
    level = "warn" if days >= 7 else "info"
    title = "上次启动与运行时长"
    if days >= 7:
        title = "超过 7 天未重启"
        detail = "长期不重启会积累更新挂起、内存碎片和驱动异常；排查卡顿/更新问题前建议先重启"
    else:
        detail = str(b) + " · 已运行 " + str(ov.get("uptime") or "")
    out.append(_finding(level, title, detail if days >= 7 else (str(b) + " · 已运行 " + str(ov.get("uptime") or ""))))
    if days >= 7:
        out.append(_finding("info", "上次启动与运行时长", str(b) + " · 已运行 " + str(ov.get("uptime") or "")))
    fast = str(ov.get("fast") or "")
    if fast in ("0", "1"):
        out.append(_finding(
            "info",
            "快速启动：" + ("已开启" if fast == "1" else "未开启"),
            "快速启动异常可导致关机不彻底、外设唤醒失败",
        ))
    startup = _list(ov.get("startup"))
    names = [str(x.get("Name") or "") for x in startup if isinstance(x, dict)]
    names = [n for n in names if n]
    n = len(names)
    if n:
        level = "warn" if n >= 20 else "ok"
        out.append(_finding(level, f"开机自启项 {n} 个", "，".join(names[:8]) + ("…" if n > 8 else "")))
    else:
        out.append(_finding("ok", "开机自启项 0 个", "未发现额外开机自启项"))
    physical = _list(ov.get("physical"))
    if physical:
        for d in physical:
            health = str(d.get("HealthStatus") or "").lower()
            level = "ok" if health == "healthy" else "err"
            name = d.get("FriendlyName") or "未知"
            detail = str(d.get("MediaType") or "") + " · " + str(d.get("OperationalStatus") or "")
            out.append(_finding(level, "硬盘 " + str(name) + "：" + (d.get("HealthStatus") or "未知"), detail))
    else:
        out.append(_finding("info", "未能读取物理硬盘健康状态", "部分系统需管理员权限"))
    return out


def _check_bsod(ctx):
    out = []
    events = ctx.get("bsod_events") or []
    n = len(events)
    if n:
        level = "err" if n >= 3 else "warn"
        summary = "；".join(
            str(e.get("TimeCreated") or "") + " ID " + str(e.get("Id") or "")
            for e in events[:4]
        )
        out.append(_finding(level, f"近 14 天异常关机/蓝屏事件 {n} 条", summary))
        latest = (events[0].get("Msg") or "").strip() if events else ""
        if latest:
            out.append(_finding("info", "最近一条错误摘要", latest))
    else:
        out.append(_finding("ok", "近 14 天未发现蓝屏/异常关机事件", "事件 ID 41 / 1001 / 6008"))
    dump = _one(_ps(
        "$d=@(Get-ChildItem 'C:\\Windows\\Minidump' -Filter *.dmp -ErrorAction SilentlyContinue | "
        "Sort-Object LastWriteTime -Descending); $latest=''; $sz=0; "
        "if($d.Count -gt 0){$latest=[string]$d[0].LastWriteTime; $sz=[math]::Round($d[0].Length/1MB,1)}; "
        "[pscustomobject]@{count=$d.Count; latest=$latest; sizeMB=$sz}"
    ))
    count = int((dump or {}).get("count") or 0)
    if count:
        out.append(_finding(
            "warn",
            f"存在 {count} 个崩溃转储文件",
            "最近 " + str((dump or {}).get("latest") or "") + " · " + str((dump or {}).get("sizeMB") or 0) + " MB，可用 BlueScreenView/WinDbg 分析",
        ))
    else:
        out.append(_finding("ok", "未发现系统崩溃转储", ""))
    memory = _list(_ps(
        "Get-CimInstance Win32_PhysicalMemory | Select-Object "
        "@{n='GB';e={[math]::Round($_.Capacity/1GB)}},Speed,Manufacturer,PartNumber"
    ))
    if memory:
        total = sum(int(m.get("GB") or 0) for m in memory)
        vendors = " ".join(str(m.get("Manufacturer") or "?") + " " + str(m.get("GB") or "") + "GB " + str(m.get("Speed") or "") + "MHz" for m in memory)
        out.append(_finding("info", f"内存 {total} GB（{len(memory)} 条）", vendors))
    errors = ctx.get("pnp_errors") or []
    if errors:
        names = "；".join(str(e.get("FriendlyName") or e.get("Class") or "未知") for e in errors[:6])
        out.append(_finding("warn", f"驱动/设备异常 {len(errors)} 个", names))
    return out


def _check_perf(ctx):
    out = []
    data = _one(_ps(
        "$cpu=Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average; "
        "$os=Get-CimInstance Win32_OperatingSystem; "
        "$pf=Get-CimInstance Win32_PageFileUsage | Select-Object Name,CurrentUsage,AllocatedBaseSize; "
        "$proc=Get-Process | Sort-Object WS -Descending | Select-Object -First 8 Name,Id,@{n='MB';e={[math]::Round($_.WS/1MB)}}; "
        "[pscustomobject]@{cpu=[math]::Round($cpu.Average); "
        "memPct=[math]::Round(($os.TotalVisibleMemorySize-$os.FreePhysicalMemory)/$os.TotalVisibleMemorySize*100); "
        "pagefile=@($pf); procs=@($proc)}"
    ))
    ov = ctx.get("overview") or {}
    if data:
        cpu = float(data.get("cpu") or 0)
        mem = float(data.get("memPct") or 0)
        out.append(_finding(
            "warn" if cpu >= 85 else "ok",
            f"CPU 占用 {cpu:.0f}%",
            "持续高占用请检查后台进程/散热",
        ))
        out.append(_finding(
            "warn" if mem >= 85 else "ok",
            f"内存占用 {mem:.0f}%",
            f"总内存 {ov.get('totalMB') or '?'} MB · 可用 {ov.get('freeMB') or '?'} MB",
        ))
        for pf in _list(data.get("pagefile")):
            try:
                alloc = float(pf.get("AllocatedBaseSize") or 0)
                used = float(pf.get("CurrentUsage") or 0)
                pct = used * 100 / alloc if alloc else 0
            except (TypeError, ValueError, ZeroDivisionError):
                continue
            out.append(_finding(
                "warn" if pct >= 80 else "info",
                "虚拟内存 " + str(pf.get("Name") or "") + f"：{used:.0f} / {alloc:.0f}",
                "使用率过高时会出现“虚拟内存不足”弹窗",
            ))
        procs = _list(data.get("procs"))
        if procs:
            top = "；".join(f"{p.get('Name')}({p.get('MB')}MB)" for p in procs[:5])
            out.append(_finding("info", "内存占用前 5 的进程", top))
    else:
        out.append(_finding("warn", "性能计数器读取失败", "可能被安全软件限制"))
    disk = _list(_ps(
        "Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk | "
        "Where-Object {$_.Name -ne '_Total'} | Select-Object Name,PercentDiskTime,AvgDiskQueueLength"
    ))
    for d in disk:
        try:
            busy = float(d.get("PercentDiskTime") or 0)
            qlen = float(d.get("AvgDiskQueueLength") or 0)
        except (TypeError, ValueError):
            continue
        if busy >= 70 or qlen >= 2:
            out.append(_finding(
                "warn",
                f"磁盘 {d.get('Name')} 繁忙 {busy:.0f}% 队列 {qlen:.1f}",
                "；检查 Windows Search/SysMain/杀毒扫描或硬盘故障",
            ))
    services = _services(["SearchIndexer", "SysMain"])
    for name, label in (("SearchIndexer", "Windows Search"), ("SysMain", "SysMain/Superfetch")):
        svc = services.get(name) or {}
        status = str(svc.get("Status") or "")
        if status:
            out.append(_finding("info", f"{label}：{status}", "若磁盘长期 100% 可尝试临时停止该服务验证"))
    return out


def _check_update(ctx):
    out = []
    data = _one(_ps(
        "$hf=Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID,@{n='date';e={[string]$_.InstalledOn}}; "
        "$pending=@(); "
        "if(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'){$pending+='CBS'}; "
        "if(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'){$pending+='WindowsUpdate'}; "
        "if(Test-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\PendingFileRenameOperations'){$pending+='PendingFileRename'}; "
        "[pscustomobject]@{hotfix=@($hf); pending=$pending}"
    ))
    hotfix = _list((data or {}).get("hotfix"))
    if hotfix:
        latest = hotfix[0]
        date = str(latest.get("date") or "")
        out.append(_finding(
            "info",
            "最近补丁 " + str(latest.get("HotFixID") or "") + ("（" + date + "）" if date else ""),
            "近 5 个：" + "，".join(str(h.get("HotFixID") or "") for h in hotfix),
        ))
        # stale?
        stale = False
        for fmt in ("%Y/%m/%d", "%m/%d/%Y", "%Y-%m-%d"):
            try:
                t = time.mktime(time.strptime(date.split(" ")[0], fmt))
                if time.time() - t > 90 * 86400:
                    stale = True
                break
            except (ValueError, IndexError, OverflowError):
                continue
        if stale:
            out.append(_finding("warn", "超过 90 天未安装补丁", "建议检查 Windows 更新"))
    else:
        out.append(_finding("info", "未读取到补丁列表", "Get-HotFix 可能被限制"))
    pending = _list((data or {}).get("pending"))
    if pending:
        out.append(_finding("warn", "存在待重启的更新/组件操作", "来源：" + "、".join(str(p) for p in pending) + "；这会导致后续更新安装失败或回滚"))
    else:
        out.append(_finding("ok", "无待重启更新标记", ""))
    svc = (_services(["wuauserv"]).get("wuauserv") or {})
    status = str(svc.get("Status") or "")
    stype = str(svc.get("StartType") or "—")
    level = "warn" if "disabled" in stype.lower() else "info"
    out.append(_finding(level, "Windows Update 服务：" + (status or "—"), "启动类型 " + stype + "（手动/按需启动时停止是正常的）"))
    events = _list(_ps(
        "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; "
        "Level=2; StartTime=(Get-Date).AddDays(-14)} -ErrorAction SilentlyContinue | "
        "Select-Object -First 6 TimeCreated,Id,@{n='Msg';e={$m=[string]$_.Message; $m.Substring(0,[Math]::Min(160,$m.Length))}}",
        20,
    ))
    if events:
        detail = "；".join((str(e.get("TimeCreated") or "") + " " + str(e.get("Msg") or "")[:80]) for e in events[:3])
        out.append(_finding("warn", f"近 14 天更新错误 {len(events)} 条", detail))
    else:
        out.append(_finding("ok", "近 14 天无更新客户端错误", ""))
    return out


def _check_device(ctx):
    out = []
    adapters = _list(_ps("Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,Status,LinkSpeed,MediaType"))
    for a in adapters:
        status = str(a.get("Status") or "").lower()
        if "not present" in status:
            continue
        level = "ok" if status == "up" else "info"
        out.append(_finding(
            level,
            "网卡 " + str(a.get("Name") or "") + "：" + str(a.get("Status") or ""),
            str(a.get("LinkSpeed") or "—") + " · " + str(a.get("MediaType") or ""),
        ))
    wlan = wlan_status()
    if wlan.get("available"):
        out.append(_finding("info", "无线网卡", "连接：" + (wlan.get("ssid") or "未连接") + " " + str(wlan.get("state") or "")))
    services = _services(["Audiosrv", "AudioEndpointBuilder", "bthserv", "BTAGService", "Spooler"])
    for name, label in (("Audiosrv", "音频服务"), ("bthserv", "蓝牙支持服务"), ("BTAGService", "蓝牙音频网关"), ("Spooler", "打印后台")):
        svc = services.get(name) or {}
        status = str(svc.get("Status") or "")
        stype = str(svc.get("StartType") or "")
        if not status:
            continue
        level = "warn" if "disabled" in stype.lower() else "info"
        extra = "（手动/按需启动时停止是正常的）" if status.lower() != "running" else ""
        out.append(_finding(level, f"{label}：{status}", "启动类型 " + stype + extra))
    printers = _list(_ps("Get-Printer -ErrorAction SilentlyContinue | Select-Object Name,PrinterStatus,JobCount"))
    for p in printers[:5]:
        jobs = int(p.get("JobCount") or 0)
        out.append(_finding(
            "warn" if jobs else "info",
            "打印机 " + str(p.get("Name") or "") + "：" + str(p.get("PrinterStatus") or "?"),
            f"队列 {jobs} 个任务",
        ))
    errors = [e for e in (ctx.get("pnp_errors") or []) if str(e.get("Class") or "") not in ("", "Net")]
    if errors:
        names = "；".join(f"{e.get('FriendlyName')}（{e.get('Status')}）" for e in errors[:6])
        out.append(_finding("warn", f"USB/音频/蓝牙等设备异常 {len(errors)} 个", names))
    return out


def _check_files(ctx):
    out = []
    data = _one(_ps(
        "$names=@('explorer','StartMenuExperienceHost','SearchHost','ShellExperienceHost'); "
        "$running=@(Get-Process -Name $names -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name -Unique); "
        "$store=Get-AppxPackage -Name Microsoft.WindowsStore -ErrorAction SilentlyContinue | "
        "Select-Object -First 1 Name,Version,Status; "
        "[pscustomobject]@{running=$running; store=$store}",
        25,
    )) or {}
    running = set(str(x) for x in _list(data.get("running")))
    for name, label in (
        ("explorer", "资源管理器"),
        ("StartMenuExperienceHost", "开始菜单"),
        ("SearchHost", "搜索"),
        ("ShellExperienceHost", "Shell 外壳"),
    ):
        ok = name.lower() in {r.lower() for r in running}
        out.append(_finding(
            "ok" if ok else "warn",
            f"进程 {label}：" + ("运行中" if ok else "未运行"),
            "" if ok else "未运行可能导致任务栏/开始菜单/搜索无响应",
        ))
    store = data.get("store") or {}
    if isinstance(store, dict) and store:
        status = store.get("Status") or "状态未知"
        out.append(_finding("info", "微软商店：" + str(status), "版本 " + str(store.get("Version") or "—")))
    ov = ctx.get("overview") or {}
    admin = bool(ov.get("admin"))
    out.append(_finding(
        "info",
        "当前权限：" + ("管理员" if admin else "普通用户"),
        "" if admin else "普通用户下部分系统修复命令无法执行",
    ))
    out.append(_finding("info", "系统文件修复命令（需管理员）", "sfc /scannow；DISM /Online /Cleanup-Image /RestoreHealth"))
    return out


def _check_license(ctx):
    out = []
    data = _one(_ps(
        '$st=(Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey is not null" '
        "-ErrorAction SilentlyContinue | Select-Object -First 1).LicenseStatus; "
        "$bl=@(Get-BitLockerVolume -ErrorAction SilentlyContinue | "
        "Select-Object MountPoint,VolumeStatus,ProtectionStatus,PercentageEncrypted); "
        "$rp=@(Get-ComputerRestorePoint -ErrorAction SilentlyContinue); "
        "[pscustomobject]@{license=$st; bitlocker=$bl; restore=$rp.Count}",
        25,
    )) or {}
    lic_map = {0: "未授权", 1: "已激活", 2: "初始宽限期", 3: "宽限期", 4: "非正版宽限期", 5: "通知模式", 6: "扩展宽限期"}
    v = data.get("license")
    if v is not None and (str(v).isdigit() or isinstance(v, (int, float))):
        code = int(v)
        status = lic_map.get(code, str(v))
        out.append(_finding(
            "ok" if code == 1 else "warn",
            "Windows 激活状态：" + status,
            "可在「设置 → 系统 → 激活」查看详情",
        ))
    else:
        out.append(_finding("info", "未能读取激活状态", "可在「设置 → 系统 → 激活」确认"))
    for d in _list(data.get("bitlocker")):
        out.append(_finding(
            "info",
            "BitLocker " + str(d.get("MountPoint") or "?") + "：" + str(d.get("ProtectionStatus") or ""),
            "卷状态 " + str(d.get("VolumeStatus") or "—") + " · 已加密 " + str(d.get("PercentageEncrypted") or 0) + "%",
        ))
    restore = data.get("restore")
    try:
        restore = int(restore)
    except (TypeError, ValueError):
        restore = 0
    out.append(_finding(
        "warn" if restore < 1 else "ok",
        f"系统还原点 {restore} 个",
        "还原点过少会减少故障回滚手段" if restore < 1 else "",
    ))
    disks = ctx.get("disks") or _disks()
    if disks:
        for d in disks:
            try:
                total = float(d.get("totalGB") or 0)
                free = float(d.get("freeGB") or 0)
                pct = free * 100 / total if total else 100
            except (TypeError, ValueError, ZeroDivisionError):
                continue
            if pct <= 8:
                level = "err"
            elif pct <= 15:
                level = "warn"
            else:
                level = "ok"
            out.append(_finding(
                level,
                f"磁盘 {d.get('DeviceID')} 剩余 {free:.1f} GB / {total:.1f} GB",
                "空间不足会影响更新、虚拟内存与休眠文件" if level != "ok" else "",
            ))
    else:
        out.append(_finding("info", "未能读取磁盘空间", ""))
    return out


def _check_misc(ctx):
    out = []
    off, src = ntp_offset("ntp.aliyun.com", 2)
    if off is None:
        out.append(_finding("warn", "系统时间偏差无法获取", "UDP 123 与 HTTP 时间源均不可达"))
    else:
        level = "warn" if abs(off) >= 60 else "ok"
        out.append(_finding(
            level,
            f"系统时间偏差 {off:+.2f} 秒",
            "来源 " + (src or "") + "；偏差过大会导致证书/登录/更新失败",
        ))
    svc = (_services(["W32Time"]).get("W32Time") or {})
    status = str(svc.get("Status") or "")
    if status:
        out.append(_finding("info", "时间同步服务：" + status, "启动类型 " + str(svc.get("StartType") or "")))
    whea = _list(_ps(
        "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; "
        "StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue | Select-Object -First 5 TimeCreated,Id",
        20,
    ))
    if whea:
        out.append(_finding("warn", f"近 7 天硬件错误 {len(whea)} 条", "WHEA 事件通常与内存/CPU/散热/供电有关，建议检查硬件"))
    else:
        out.append(_finding("ok", "近 7 天无 WHEA 硬件错误", ""))
    plan, _ = run_cmd(["cmd", "/c", "powercfg /getactivescheme"], timeout=10)
    if plan:
        out.append(_finding("info", "当前电源计划", plan.strip()[:120]))
    return out


CHECKS = {
    "boot": _check_boot,
    "bsod": _check_bsod,
    "perf": _check_perf,
    "update": _check_update,
    "device": _check_device,
    "files": _check_files,
    "license": _check_license,
    "misc": _check_misc,
}


def windiag_stream(scope="all", focus=""):
    scope = scope or "all"
    if scope != "all" and scope not in dict(CATEGORIES):
        raise ValueError("未知的诊断范围")
    selected = list(CATEGORIES) if scope == "all" else [c for c in CATEGORIES if c[0] == scope]
    ids = [c[0] for c in selected]
    total = len(ids)
    yield {"type": "start", "scope": scope, "focus": focus or ""}
    yield {"type": "stage", "step": 0, "total": total, "text": "系统基础信息"}
    ctx = {}
    with ThreadPoolExecutor(max_workers=5) as pool:
        pre = {
            "boot": pool.submit(_boot_bundle),
            "overview": pool.submit(_overview),
            "disks": pool.submit(_disks),
            "pnp_errors": pool.submit(_pnp_errors),
        }
        if "bsod" in ids:
            pre["bsod_events"] = pool.submit(_events, [41, 1001, 6008], 14)
        for key, fut in pre.items():
            try:
                ctx[key] = fut.result()
            except Exception:
                ctx[key] = None
        if not ctx.get("overview"):
            ctx["overview"] = ctx.get("boot")

    counts = {"ok": 0, "warn": 0, "err": 0, "info": 0}
    issues = []
    futures = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for cid, title in selected:
            futures[pool.submit(CHECKS[cid], ctx)] = (cid, title)
        for i, (cid, title) in enumerate(selected, 1):
            yield {"type": "stage", "step": i, "total": total, "text": title}
        for fut in as_completed(futures):
            cid, title = futures[fut]
            try:
                findings = fut.result() or []
            except Exception as e:
                findings = [_finding("warn", title + " 检查失败", f"{type(e).__name__}: {e}")]
            for f in findings:
                counts[f.get("level", "info")] = counts.get(f.get("level", "info"), 0) + 1
                if f.get("level") in ("warn", "err"):
                    issues.append({"level": f.get("level"), "title": f.get("title"), "detail": f.get("detail")})
                yield f
    yield {
        "type": "summary",
        "counts": counts,
        "total": sum(counts.values()),
        "issues": issues,
        "categories": [c[0] for c in selected],
    }
    yield {"type": "done"}
