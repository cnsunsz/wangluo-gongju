"""读取 / 写入经典 pcap，并尽量读取常见 pcapng（SHB + IDB + EPB / SPB）。"""
from __future__ import annotations

import struct
from typing import Iterable

# 经典 pcap 魔术数
MAGIC_US_LE = 0xA1B2C3D4
MAGIC_US_BE = 0xD4C3B2A1
MAGIC_NS_LE = 0xA1B23C4D
MAGIC_NS_BE = 0x4D3CB2A1

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_BYTE_ORDER_LE = 0x1A2B3C4D
PCAPNG_BYTE_ORDER_BE = 0x4D3C2B1A
PCAPNG_IDB = 0x00000001
PCAPNG_SPB = 0x00000003
PCAPNG_EPB = 0x00000006
PCAPNG_NRB = 0x00000004
PCAPNG_ISB = 0x00000005
PCAPNG_DSB = 0x0000000A

# 写出时使用微秒精度、小端经典 pcap
WRITE_MAGIC = MAGIC_US_LE


class PcapError(ValueError):
    pass


def sniff_format(data: bytes) -> str:
    if len(data) < 4:
        return "unknown"
    mag = int.from_bytes(data[:4], "little")
    magb = int.from_bytes(data[:4], "big")
    if mag in (MAGIC_US_LE, MAGIC_NS_LE) or magb in (MAGIC_US_LE, MAGIC_NS_LE, MAGIC_US_BE, MAGIC_NS_BE):
        # 上面覆盖不完整，下面再判
        pass
    if mag in (MAGIC_US_LE, MAGIC_NS_LE, MAGIC_US_BE, MAGIC_NS_BE):
        return "pcap"
    if magb in (MAGIC_US_LE, MAGIC_NS_LE):
        return "pcap"
    if mag == PCAPNG_SHB or magb == PCAPNG_SHB or data[:4] == b"\x0a\x0d\x0d\x0a":
        return "pcapng"
    return "unknown"


def read_packets(data: bytes) -> dict:
    """返回 {linktype, packets:[{ts, incl_len, orig_len, data, ifindex, linktype}], warnings, format}."""
    kind = sniff_format(data)
    if kind == "pcap":
        return _read_pcap(data)
    if kind == "pcapng":
        return _read_pcapng(data)
    raise PcapError("无法识别文件格式。请打开经典 .pcap，或由 Wireshark / tcpdump 导出的常见 .pcapng。")


def _read_pcap(data: bytes) -> dict:
    if len(data) < 24:
        raise PcapError("pcap 文件过短，缺少全局头。")
    magic = int.from_bytes(data[:4], "little")
    if magic in (MAGIC_US_LE, MAGIC_NS_LE):
        endian = "<"
        ns = magic == MAGIC_NS_LE
    else:
        magic_be = int.from_bytes(data[:4], "big")
        if magic_be in (MAGIC_US_LE, MAGIC_NS_LE):
            endian = ">"
            ns = magic_be == MAGIC_NS_LE
        else:
            raise PcapError("不是有效的 pcap 魔术数。")
    _vmaj, _vmin, _zone, _sig, snaplen, network = struct.unpack(endian + "HHiIII", data[4:24])
    packets = []
    off = 24
    n = 0
    warnings: list[str] = []
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if incl > 0x1000000:  # 16MB 单包防御
            warnings.append(f"第 {n + 1} 个包的捕获长度异常（{incl}），停止继续读取。")
            break
        if off + incl > len(data):
            warnings.append(f"第 {n + 1} 个包数据被截断（需要 {incl} 字节，文件剩余 {len(data) - off}）。")
            payload = data[off:]
            packets.append({
                "ts": ts_sec + (ts_frac / 1e9 if ns else ts_frac / 1e6),
                "incl_len": len(payload),
                "orig_len": orig,
                "data": payload,
                "ifindex": 0,
                "linktype": network,
            })
            break
        payload = data[off:off + incl]
        off += incl
        n += 1
        packets.append({
            "ts": ts_sec + (ts_frac / 1e9 if ns else ts_frac / 1e6),
            "incl_len": incl,
            "orig_len": orig,
            "data": payload,
            "ifindex": 0,
            "linktype": network,
        })
    return {
        "format": "pcap",
        "linktype": network,
        "snaplen": snaplen,
        "packets": packets,
        "warnings": warnings,
    }


def _u32(data: bytes, off: int, endian: str) -> int:
    return struct.unpack(endian + "I", data[off:off + 4])[0]


def _read_pcapng(data: bytes) -> dict:
    if len(data) < 16 or data[:4] != b"\x0a\x0d\x0d\x0a":
        raise PcapError("不是有效的 pcapng（缺少 Section Header Block）。")
    warnings: list[str] = []
    # 先用 SHB 里的字节序
    if len(data) < 16:
        raise PcapError("pcapng 过短。")
    # total_length 还不知道字节序，先读 BOM
    # SHB: type(4 already) + total_len(4) + bom(4)
    # 试 little
    bom_le = int.from_bytes(data[8:12], "little")
    bom_be = int.from_bytes(data[8:12], "big")
    if bom_le == PCAPNG_BYTE_ORDER_LE:
        endian = "<"
    elif bom_be == PCAPNG_BYTE_ORDER_BE or int.from_bytes(data[8:12], "big") == PCAPNG_BYTE_ORDER_LE:
        # 若文件是大端，BOM 以大端写出 0x1A2B3C4D，bytes 为 1A 2B 3C 4D，little 读是 0x4D3C2B1A
        if int.from_bytes(data[8:12], "big") == PCAPNG_BYTE_ORDER_LE:
            endian = ">"
        elif bom_le == PCAPNG_BYTE_ORDER_BE:
            endian = ">"
        else:
            endian = "<"
    else:
        # 常见都是小端
        if bom_le == PCAPNG_BYTE_ORDER_BE:
            endian = ">"
        else:
            warnings.append("未能确认 pcapng 字节序，按小端尝试。部分块可能读失败。")
            endian = "<"

    ifaces: dict[int, dict] = {}
    packets: list[dict] = []
    off = 0
    default_link = 1
    unknown_blocks = 0
    while off + 12 <= len(data):
        btype = _u32(data, off, endian)
        blen = _u32(data, off + 4, endian)
        if blen < 12 or off + blen > len(data):
            # 可能字节序错了，或文件截断
            if off == 0:
                raise PcapError("pcapng 块长度异常，可能不是常见格式。")
            warnings.append(f"在偏移 {off} 处块长度异常（type=0x{btype:08x}, len={blen}），停止读取。")
            break
        body = data[off + 8:off + blen - 4]
        tail = _u32(data, off + blen - 4, endian)
        if tail != blen:
            warnings.append(f"块尾长度不一致（type=0x{btype:08x}），文件可能损坏。")
        if btype == PCAPNG_SHB:
            # 新的 section，接口编号重计
            ifaces = {}
        elif btype == PCAPNG_IDB:
            if len(body) >= 4:
                linktype = struct.unpack(endian + "H", body[0:2])[0]
                snaplen = _u32(data, off + 8 + 4, endian) if len(body) >= 8 else 0
                idx = len(ifaces)
                ifaces[idx] = {"linktype": linktype, "snaplen": snaplen}
                default_link = linktype
        elif btype == PCAPNG_EPB:
            if len(body) >= 20:
                if_id = _u32(data, off + 8, endian)
                ts_hi = _u32(data, off + 12, endian)
                ts_lo = _u32(data, off + 16, endian)
                caplen = _u32(data, off + 20, endian)
                origlen = _u32(data, off + 24, endian)
                pkt = body[20:20 + caplen]
                ts_raw = (ts_hi << 32) | ts_lo
                # 默认分辨率微秒（IDB if_tsresol 缺省 10^-6）
                resol = ifaces.get(if_id, {}).get("tsresol", 1_000_000)
                ts = ts_raw / float(resol)
                link = ifaces.get(if_id, {}).get("linktype", default_link)
                packets.append({
                    "ts": ts,
                    "incl_len": len(pkt),
                    "orig_len": origlen,
                    "data": pkt,
                    "ifindex": if_id,
                    "linktype": link,
                })
            else:
                warnings.append("遇到过短的 Enhanced Packet Block，已跳过。")
        elif btype == PCAPNG_SPB:
            if len(body) >= 4:
                origlen = _u32(data, off + 8, endian)
                # caplen = min(origlen, snaplen of if 0)
                snap = ifaces.get(0, {}).get("snaplen") or origlen
                caplen = min(origlen, snap, len(body) - 4)
                pkt = body[4:4 + caplen]
                link = ifaces.get(0, {}).get("linktype", default_link)
                packets.append({
                    "ts": 0.0,
                    "incl_len": len(pkt),
                    "orig_len": origlen,
                    "data": pkt,
                    "ifindex": 0,
                    "linktype": link,
                })
        elif btype in (PCAPNG_NRB, PCAPNG_ISB, PCAPNG_DSB, 0x00000BAD, 0x40000BAD):
            pass
        else:
            unknown_blocks += 1
        off += blen
        # 块长度应 4 字节对齐（已包含在 blen 中）

    if unknown_blocks:
        warnings.append(f"已跳过 {unknown_blocks} 个未识别的 pcapng 块。若结果不完整，请用 Wireshark 另存为经典 pcap 后再打开。")
    if not ifaces and not packets:
        warnings.append("pcapng 中没有读到接口或数据包。若这是含自定义块的文件，请另存为 .pcap。")
    linktype = default_link
    if ifaces:
        linktype = ifaces[min(ifaces)].get("linktype", default_link)
    return {
        "format": "pcapng",
        "linktype": linktype,
        "snaplen": 0,
        "packets": packets,
        "warnings": warnings,
        "interfaces": {str(k): v for k, v in ifaces.items()},
    }


def write_pcap(packets: Iterable[dict], linktype: int = 1, snaplen: int = 65535) -> bytes:
    """把报文写成经典微秒精度小端 pcap。packets 项需含 data，可选 ts / orig_len。"""
    parts = [struct.pack("<IHHIIII", WRITE_MAGIC, 2, 4, 0, 0, snaplen or 65535, int(linktype))]
    for pkt in packets:
        raw = pkt["data"] if isinstance(pkt, dict) else pkt
        if not isinstance(raw, (bytes, bytearray)):
            raise PcapError("报文数据不是字节。")
        ts = float(pkt.get("ts") or 0.0) if isinstance(pkt, dict) else 0.0
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:
            sec += 1
            usec -= 1_000_000
        if usec < 0:
            usec = 0
        incl = len(raw)
        orig = int(pkt.get("orig_len") or incl) if isinstance(pkt, dict) else incl
        parts.append(struct.pack("<IIII", sec, usec, incl, orig))
        parts.append(bytes(raw))
    return b"".join(parts)
