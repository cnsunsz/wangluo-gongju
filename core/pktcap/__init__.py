"""本机网络抓包与报文解析。

独立实现类 Wireshark 的包列表、逐层字段和字节视图，不嵌入或再分发 Wireshark / tshark，
也不再分发 Npcap。实时抓包通过系统 libpcap / Npcap 的公开 API；打开 pcap 不依赖它们。
"""

from core.pktcap.session import (
    BPF_PRESETS,
    DEFAULT_MAX_BYTES,
    DEFAULT_MAX_PACKETS,
    capability,
    clear_packets,
    conversations,
    deep_analyze_brief,
    diagnose,
    follow_stream,
    list_interfaces,
    open_bytes,
    open_path,
    packet_detail,
    packet_summaries,
    protocol_stats,
    save_bytes,
    save_path,
    start_capture,
    status,
    stop_capture,
)

__all__ = [
    "BPF_PRESETS",
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_PACKETS",
    "capability",
    "clear_packets",
    "conversations",
    "deep_analyze_brief",
    "diagnose",
    "follow_stream",
    "list_interfaces",
    "open_bytes",
    "open_path",
    "packet_detail",
    "packet_summaries",
    "protocol_stats",
    "save_bytes",
    "save_path",
    "start_capture",
    "status",
    "stop_capture",
]
