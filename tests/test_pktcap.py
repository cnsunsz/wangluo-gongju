#!/usr/bin/env python3
"""合成 pcap 回放测试：摘要、逐层字段、偏移对齐、过滤、跟踪流、能力检查。"""
from __future__ import annotations

import ipaddress
import os
import struct
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.pktcap.dissect import dissect, match_filter
from core.pktcap.pcapfile import read_packets, write_pcap, sniff_format, PcapError
from core.pktcap import session


def mac(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def ipv4(s: str) -> bytes:
    return bytes(int(x) for x in s.split("."))


def ipv6(s: str) -> bytes:
    return ipaddress.IPv6Address(s).packed


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def eth(dst, src, etype, payload) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", etype) + payload


def ipv4_pkt(src, dst, proto, payload, ttl=64, dscp=0, ident=0x1234, flags=2) -> bytes:
    ihl = 20
    tos = (dscp << 2) & 0xFC
    total = ihl + len(payload)
    flags_frag = (flags << 13)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, tos, total, ident, flags_frag, ttl, proto, 0,
                      ipv4(src), ipv4(dst))
    csum = checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def ipv6_pkt(src, dst, nxt, payload, hlim=64) -> bytes:
    hdr = struct.pack("!IHBB", 0x60000000, len(payload), nxt, hlim) + ipv6(src) + ipv6(dst)
    return hdr + payload


def tcp_seg(sport, dport, seq, ack, flags, payload=b"", window=65535, opts=b"") -> bytes:
    if opts and len(opts) % 4:
        opts += b"\x00" * (4 - len(opts) % 4)
    doff = (20 + len(opts)) // 4
    doff_flags = (doff << 12) | (flags & 0x1FF)
    hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, doff_flags, window, 0, 0) + opts
    return hdr + payload


def udp_dgram(sport, dport, payload) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def icmp_echo(typ=8, ident=1, seq=1, payload=b"abcd") -> bytes:
    hdr = struct.pack("!BBHHH", typ, 0, 0, ident, seq) + payload
    csum = checksum(hdr)
    return struct.pack("!BBHHH", typ, 0, csum, ident, seq) + payload


def arp_who_has(spa, tpa, sha="02:00:00:00:00:01") -> bytes:
    return struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac(sha) + ipv4(spa) + (b"\x00" * 6) + ipv4(tpa)


def dns_query(name="www.example.com", typ=1, tid=0x1234) -> bytes:
    def enc(n):
        out = b""
        for lab in n.split("."):
            b = lab.encode()
            out += bytes([len(b)]) + b
        return out + b"\x00"
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    return header + enc(name) + struct.pack("!HH", typ, 1)


def dns_answer(name="www.example.com", ip="93.184.216.34", typ=1, tid=0x1234) -> bytes:
    def enc(n):
        out = b""
        for lab in n.split("."):
            b = lab.encode()
            out += bytes([len(b)]) + b
        return out + b"\x00"
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    q = enc(name) + struct.pack("!HH", typ, 1)
    # pointer to name at offset 12
    rr = struct.pack("!HHHIH4s", 0xC00C, typ, 1, 60, 4, ipv4(ip))
    return header + q + rr


def http_get(path="/index.html", host="example.com") -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netmeter-test\r\n\r\n").encode()


def http_resp() -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"


def tls_client_hello(sni="example.com") -> bytes:
    # Minimal TLS 1.2 ClientHello with SNI
    sni_b = sni.encode()
    # server_name list: list_len + name_type + name_len + name
    sn_list = struct.pack("!HBH", 1 + 2 + len(sni_b), 0, len(sni_b)) + sni_b
    ext_sni = struct.pack("!HH", 0, len(sn_list)) + sn_list
    exts = ext_sni
    # client_version + random(32) + sid_len(0) + cipher_suites + comp
    random = b"\x11" * 32
    ciphers = struct.pack("!HH", 2, 0x002F)  # len + TLS_RSA_WITH_AES_128_CBC_SHA
    body = struct.pack("!H", 0x0303) + random + b"\x00" + ciphers + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    hs = bytes([1]) + len(body).to_bytes(3, "big") + body
    rec = bytes([22]) + struct.pack("!HH", 0x0303, len(hs)) + hs
    return rec


def frame(dst, src, l3) -> bytes:
    # detect ip version
    ver = l3[0] >> 4
    if ver == 4:
        et = 0x0800
    elif ver == 6:
        et = 0x86DD
    else:
        et = 0x0806
    return eth(dst, src, et, l3)


def collect_offsets(nodes, acc=None):
    acc = acc if acc is not None else []
    for n in nodes or []:
        acc.append((n.get("name"), n.get("offset", 0), n.get("length", 0), n.get("value")))
        collect_offsets(n.get("children") or [], acc)
    return acc


def field_value(layers, name_substr) -> str | None:
    for name, off, ln, val in collect_offsets(layers):
        if name and name_substr.lower() in name.lower() and val:
            return val
    return None


def find_node(layers, name_substr):
    for n in layers or []:
        if name_substr.lower() in (n.get("name") or "").lower():
            return n
        got = find_node(n.get("children") or [], name_substr)
        if got:
            return got
    return None


class TestDissect(unittest.TestCase):
    def test_arp(self):
        raw = eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x0806,
                  arp_who_has("192.168.1.10", "192.168.1.1"))
        v = dissect(raw, ts=1_700_000_000.123456, number=1)
        self.assertEqual(v["protocol"], "ARP")
        self.assertIn("Who has 192.168.1.1", v["info"])
        self.assertEqual(v["src"], "192.168.1.10")
        self.assertEqual(v["dst"], "192.168.1.1")
        sha = find_node(v["layers"], "Sender MAC")
        self.assertIsNotNone(sha)
        self.assertEqual(sha["offset"], 22)
        self.assertEqual(sha["length"], 6)
        self.assertEqual(raw[22:28], mac("02:00:00:00:00:01"))

    def test_icmp(self):
        raw = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.0.0.1", "10.0.0.2", 1, icmp_echo(8, 7, 9, b"ping")))
        v = dissect(raw, number=2)
        self.assertEqual(v["protocol"], "ICMP")
        self.assertIn("Echo (ping) request", v["info"])
        self.assertIn("id=7", v["info"])
        self.assertIn("seq=9", v["info"])
        ident = find_node(v["layers"], "Identifier")
        self.assertEqual(ident["length"], 2)
        off = ident["offset"]
        self.assertEqual(struct.unpack("!H", raw[off:off + 2])[0], 7)
        ttl = find_node(v["layers"], "Time to Live")
        self.assertEqual(int(ttl["value"]), 64)
        self.assertEqual(raw[ttl["offset"]], 64)

    def test_tcp_http(self):
        payload = http_get("/hello", "www.example.com")
        l4 = tcp_seg(54321, 80, 1000, 1, 0x18, payload)  # PSH ACK
        raw = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("192.0.2.10", "192.0.2.20", 6, l4, dscp=46, ttl=55))
        v = dissect(raw, number=3)
        self.assertEqual(v["protocol"], "HTTP")
        self.assertIn("GET /hello", v["info"])
        self.assertIn("www.example.com", v["info"])
        self.assertEqual(v["src"], "192.0.2.10")
        self.assertEqual(v["dst"], "192.0.2.20")
        self.assertEqual(v["sport"], 54321)
        self.assertEqual(v["dport"], 80)
        dscp = find_node(v["layers"], "DSCP")
        self.assertIn("46", dscp["value"])
        self.assertIn("EF", dscp["value"])
        sport = find_node(v["layers"], "Source Port")
        self.assertEqual(sport["offset"], 14 + 20)
        self.assertEqual(struct.unpack("!H", raw[sport["offset"]:sport["offset"] + 2])[0], 54321)
        host = find_node(v["layers"], "Host")
        self.assertIsNotNone(host)
        self.assertEqual(host["value"], "www.example.com")
        raw_host = raw[host["offset"]:host["offset"] + host["length"]]
        self.assertIn(b"Host", raw_host)
        tcp = find_node(v["layers"], "Transmission Control Protocol")
        self.assertIsNotNone(tcp)
        flags = find_node(tcp.get("children") or [], "Flags")
        self.assertIn("PSH", flags["value"])
        self.assertIn("ACK", flags["value"])

    def test_http_response(self):
        l4 = tcp_seg(80, 54321, 1, 1000, 0x18, http_resp())
        raw = frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                    ipv4_pkt("192.0.2.20", "192.0.2.10", 6, l4))
        v = dissect(raw, number=4)
        self.assertEqual(v["protocol"], "HTTP")
        self.assertIn("200", v["info"])

    def test_udp_dns_query_and_answer(self):
        q = udp_dgram(33333, 53, dns_query("www.example.com", 1, 0xABCD))
        raw_q = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                      ipv4_pkt("10.1.1.2", "10.1.1.1", 17, q))
        vq = dissect(raw_q, number=5)
        self.assertEqual(vq["protocol"], "DNS")
        self.assertIn("0xabcd", vq["info"].lower())
        self.assertIn("www.example.com", vq["info"])
        self.assertIn("A ", vq["info"] + " ")
        tid = find_node(vq["layers"], "Transaction ID")
        self.assertEqual(tid["offset"], 14 + 20 + 8)
        self.assertEqual(struct.unpack("!H", raw_q[tid["offset"]:tid["offset"] + 2])[0], 0xABCD)

        a = udp_dgram(53, 33333, dns_answer("www.example.com", "93.184.216.34", 1, 0xABCD))
        raw_a = frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                      ipv4_pkt("10.1.1.1", "10.1.1.2", 17, a))
        va = dissect(raw_a, number=6)
        self.assertEqual(va["protocol"], "DNS")
        self.assertIn("response", va["info"].lower())
        self.assertIn("93.184.216.34", va["info"])
        # A record rdata should align
        rdata = find_node(va["layers"], "RDATA")
        self.assertIsNotNone(rdata)
        self.assertEqual(rdata["value"], "93.184.216.34")
        self.assertEqual(raw_a[rdata["offset"]:rdata["offset"] + 4], ipv4("93.184.216.34"))

    def test_tls_sni(self):
        hello = tls_client_hello("sni.example.org")
        l4 = tcp_seg(44444, 443, 10, 0, 0x18, hello)
        raw = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("198.51.100.10", "198.51.100.20", 6, l4))
        v = dissect(raw, number=7)
        self.assertEqual(v["protocol"], "TLS")
        self.assertIn("Client Hello", v["info"])
        self.assertIn("sni.example.org", v["info"])
        host = find_node(v["layers"], "Host Name")
        self.assertIsNotNone(host)
        self.assertEqual(host["value"], "sni.example.org")
        self.assertEqual(raw[host["offset"]:host["offset"] + host["length"]], b"sni.example.org")
        rec_type = find_node(v["layers"], "Content Type")
        self.assertIn("Handshake", rec_type["value"])
        ver = find_node(v["layers"], "Client Version")
        self.assertTrue(ver and "TLS" in ver["value"])

    def test_ipv6_tcp(self):
        l4 = tcp_seg(1111, 22, 1, 0, 0x02)  # SYN
        raw = eth("02:00:00:00:00:02", "02:00:00:00:00:01", 0x86DD,
                  ipv6_pkt("2001:db8::1", "2001:db8::2", 6, l4))
        v = dissect(raw, number=8)
        self.assertEqual(v["src"], "2001:db8::1")
        self.assertEqual(v["dst"], "2001:db8::2")
        self.assertEqual(v["protocol"], "TCP")
        self.assertIn("SYN", v["info"])
        ip = find_node(v["layers"], "Internet Protocol Version 6")
        self.assertIsNotNone(ip)
        src = find_node(v["layers"], "Source Address")
        self.assertEqual(src["length"], 16)
        self.assertEqual(raw[src["offset"]:src["offset"] + 16], ipv6("2001:db8::1"))

    def test_filter(self):
        raw = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(9, 80, 1, 0, 0x02)))
        v = dissect(raw, number=1)
        self.assertTrue(match_filter(v, "tcp"))
        self.assertTrue(match_filter(v, "port 80"))
        self.assertTrue(match_filter(v, "ip.addr==10.0.0.1"))
        self.assertTrue(match_filter(v, "tcp.port == 80"))
        self.assertFalse(match_filter(v, "udp"))
        self.assertFalse(match_filter(v, "port 443"))
        self.assertTrue(match_filter(v, "tcp or udp"))
        self.assertTrue(match_filter(v, "SYN"))

    def test_tcp_options_and_seq(self):
        opts = bytes([2, 4, 0x05, 0xB4, 1, 3, 3, 8, 4, 2, 1, 1])  # MSS 1460, NOP, WS 8, SACK_PERM, NOP NOP
        l4 = tcp_seg(1234, 443, 999, 0, 0x02, b"", opts=opts)
        raw = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.0.0.1", "10.0.0.2", 6, l4))
        v = dissect(raw, number=9)
        self.assertIn("MSS=1460", v["info"])
        self.assertIn("WS=8", v["info"])
        self.assertIn("SACK_PERM", v["info"])
        seq = find_node(v["layers"], "Sequence Number")
        self.assertEqual(seq["value"], "999")
        self.assertEqual(struct.unpack("!I", raw[seq["offset"]:seq["offset"] + 4])[0], 999)


class TestPcapIO(unittest.TestCase):
    def _sample_packets(self):
        frames = []
        frames.append(eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x0806,
                          arp_who_has("192.168.1.10", "192.168.1.1")))
        frames.append(frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                            ipv4_pkt("10.0.0.1", "10.0.0.2", 1, icmp_echo())))
        frames.append(frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                            ipv4_pkt("10.0.0.1", "10.0.0.2", 17,
                                     udp_dgram(12345, 53, dns_query()))))
        frames.append(frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                            ipv4_pkt("10.0.0.1", "10.0.0.2", 6,
                                     tcp_seg(1111, 80, 1, 0, 0x18, http_get()))))
        return frames

    def test_roundtrip_pcap(self):
        frames = self._sample_packets()
        blob = write_pcap([{"ts": 1000.5 + i, "data": f} for i, f in enumerate(frames)], linktype=1)
        self.assertEqual(sniff_format(blob), "pcap")
        parsed = read_packets(blob)
        self.assertEqual(parsed["format"], "pcap")
        self.assertEqual(len(parsed["packets"]), 4)
        self.assertEqual(parsed["packets"][0]["data"], frames[0])
        self.assertAlmostEqual(parsed["packets"][0]["ts"], 1000.5, places=5)

    def test_pcapng_epb(self):
        frame = self._sample_packets()[0]
        # Build a minimal little-endian pcapng: SHB + IDB + EPB
        def block(typ, body):
            # total length includes type, two lengths, body, padded to 4
            pad = (4 - (len(body) % 4)) % 4
            body2 = body + b"\x00" * pad
            total = 12 + len(body2)
            return struct.pack("<II", typ, total) + body2 + struct.pack("<I", total)

        shb_body = struct.pack("<IHH", 0x1A2B3C4D, 1, 0) + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # bom, ver, section len -1? use 0
        # section length is int64 -1 typically
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        idb_body = struct.pack("<HHI", 1, 0, 65535)  # ethernet, reserved, snaplen
        cap = len(frame)
        ts = 1_700_000_000_123456  # micro
        epb_body = struct.pack("<IIIIII", 0, ts >> 32, ts & 0xFFFFFFFF, cap, cap, 0)[:20] + frame
        # fix: if_id, ts_hi, ts_lo, caplen, origlen + pkt + pad
        epb_body = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, cap, cap) + frame
        data = block(0x0A0D0D0A, shb_body) + block(1, idb_body) + block(6, epb_body)
        self.assertEqual(sniff_format(data), "pcapng")
        parsed = read_packets(data)
        self.assertEqual(parsed["format"], "pcapng")
        self.assertEqual(len(parsed["packets"]), 1)
        self.assertEqual(parsed["packets"][0]["data"], frame)

    def test_bad_file(self):
        with self.assertRaises(PcapError):
            read_packets(b"not a pcap")


class TestSession(unittest.TestCase):
    def setUp(self):
        session.clear_packets()

    def test_open_and_detail(self):
        frames = [
            eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x0806, arp_who_has("192.168.0.2", "192.168.0.1")),
            frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                  ipv4_pkt("192.168.0.2", "192.168.0.1", 6,
                           tcp_seg(4000, 80, 10, 0, 0x18, http_get("/a", "h.test")))),
        ]
        blob = write_pcap([{"ts": 10 + i * 0.001, "data": f} for i, f in enumerate(frames)])
        st = session.open_bytes(blob, name="unit.pcap")
        self.assertEqual(st["count"], 2)
        self.assertEqual(st["source"], "file")
        sm = session.packet_summaries(after=0, limit=10)
        self.assertEqual(len(sm["packets"]), 2)
        self.assertEqual(sm["packets"][0]["protocol"], "ARP")
        self.assertEqual(sm["packets"][1]["protocol"], "HTTP")
        d = session.packet_detail(2)
        self.assertEqual(d["protocol"], "HTTP")
        self.assertTrue(d["raw_b64"])
        self.assertTrue(d["layers"])
        # stats
        stt = session.protocol_stats()
        protos = {r["protocol"] for r in stt["protocols"]}
        self.assertIn("ARP", protos)
        self.assertIn("HTTP", protos)
        # download rewrite
        data, name = session.save_bytes()
        self.assertTrue(name.endswith(".pcap"))
        parsed = read_packets(data)
        self.assertEqual(len(parsed["packets"]), 2)

    def test_follow_tcp(self):
        p1 = b"HELLO"
        p2 = b" world"
        f1 = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                   ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(1234, 80, 100, 1, 0x18, p1)))
        f2 = frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                   ipv4_pkt("10.0.0.2", "10.0.0.1", 6, tcp_seg(80, 1234, 1, 105, 0x18, b"ACK-BODY")))
        f3 = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                   ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(1234, 80, 105, 9, 0x18, p2)))
        blob = write_pcap([{"ts": i, "data": f} for i, f in enumerate((f1, f2, f3))])
        session.open_bytes(blob)
        fol = session.follow_stream(1)
        self.assertEqual(fol["packet_count"], 3)
        self.assertIn("HELLO", fol["text"])
        self.assertIn("world", fol["text"])
        self.assertIn("ACK-BODY", fol["text"])
        self.assertFalse(fol["is_binary"])

    def test_memory_limit_drop_oldest(self):
        frames = []
        for i in range(8):
            frames.append(frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                                ipv4_pkt("10.0.0.1", "10.0.0.2", 17,
                                         udp_dgram(1000 + i, 53, dns_query(f"h{i}.test")))))
        blob = write_pcap([{"ts": i, "data": f} for i, f in enumerate(frames)])
        session.open_bytes(blob, max_packets=5)
        st = session.status()
        self.assertEqual(st["count"], 5)
        self.assertTrue(st["warning"] or st["file_warnings"])
        nos = [p["no"] for p in session.packet_summaries(limit=20)["packets"]]
        self.assertEqual(nos, [1, 2, 3, 4, 5])

    def test_capability_no_crash(self):
        cap = session.capability()
        self.assertTrue(cap["can_offline"])
        self.assertIn("messages", cap)
        self.assertTrue(isinstance(cap["live_available"], bool))
        self.assertTrue(cap["presets"])
        # listing interfaces must not raise even if libpcap missing
        info = session.list_interfaces()
        self.assertIn("interfaces", info)
        self.assertTrue(info["can_offline"])
        # starting without iface should fail clearly
        with self.assertRaises(Exception):
            session.start_capture("")


class TestImports(unittest.TestCase):
    def test_modules_import(self):
        import core.pktcap
        import core.pktcap.dissect
        import core.pktcap.pcapfile
        import core.pktcap.libpcap
        import core.pktcap.session
        import core.pktcap.analysis
        # libpcap load must not throw
        lib, path, err = core.pktcap.libpcap.load()
        self.assertTrue(lib is None or lib is not None)




class TestAnalysis(unittest.TestCase):
    def _open(self, frames, ts0=1_700_000_000.0):
        blob = write_pcap([{"ts": ts0 + i * 0.001, "data": f} for i, f in enumerate(frames)])
        session.clear_packets()
        session.open_bytes(blob, name="analysis-test.pcap")
        return session

    def _detail(self, no):
        d = session.packet_detail(no)
        self.assertTrue(d.get("analysis"))
        self.assertTrue(d["analysis"].get("summary"))
        cons = d["analysis"].get("conclusions") or []
        self.assertTrue(cons, "每条可解析报文都应有非空分析结论")
        for c in cons:
            self.assertTrue(c.get("title"), c)
            self.assertTrue(c.get("detail"), c)
            self.assertIn(c.get("level"), ("info", "warn", "error", "note", None))
        return d

    def _concl_text(self, analysis):
        parts = []
        for c in analysis.get("conclusions") or []:
            parts.append((c.get("title") or "") + " " + (c.get("detail") or "") + " " + (c.get("evidence") or ""))
        return "\n".join(parts)

    def test_tcp_handshake_and_fin_ack(self):
        syn = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(40000, 443, 1000, 0, 0x02)))
        synack = frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                       ipv4_pkt("10.0.0.2", "10.0.0.1", 6, tcp_seg(443, 40000, 2000, 1001, 0x12)))
        ack = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(40000, 443, 1001, 2001, 0x10)))
        fin = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(40000, 443, 1001, 2001, 0x11)))
        self._open([syn, synack, ack, fin])
        a1 = self._detail(1)["analysis"]
        self.assertIn("SYN", a1["summary"])
        self.assertIn("第一", a1["summary"])
        t1 = self._concl_text(a1)
        self.assertIn("三次握手第 1 拍", t1)
        self.assertIn("SYN", t1)
        a2 = self._detail(2)["analysis"]
        self.assertIn("SYN-ACK", a2["summary"])
        self.assertIn("第二", a2["summary"])
        t2 = self._concl_text(a2)
        self.assertIn("三次握手第 2 拍", t2)
        self.assertIn("SYN-ACK", t2)
        a3 = self._detail(3)["analysis"]
        self.assertIn("ACK", a3["summary"])
        self.assertTrue(any("纯 ACK" in (h.get("text") or "") or "第三拍" in a3["summary"] for h in a3["hints"]) or "第三拍" in a3["summary"])
        t3 = self._concl_text(a3)
        self.assertTrue("三次握手第 3 拍" in t3 or "纯 ACK" in t3)
        a4 = self._detail(4)["analysis"]
        self.assertIn("FIN", a4["summary"])
        self.assertTrue("关闭" in a4["summary"] or any("FIN" in (h.get("text") or "") for h in a4["hints"]))
        t4 = self._concl_text(a4)
        self.assertIn("关闭", t4)
        self.assertIn("FIN", t4)
        diag = session.diagnose()
        titles = [c["title"] for c in diag["conclusions"]]
        self.assertIn("TCP 握手", titles)
        handshake = next(c for c in diag["conclusions"] if c["title"] == "TCP 握手")
        self.assertIn("完成", handshake["detail"])
        closing = next(c for c in diag["conclusions"] if c["title"] == "连接关闭")
        self.assertIn("FIN", closing["detail"])

    def test_pure_ack_and_dns_http_arp_icmp_tls(self):
        # 独立的无载荷 ACK（无握手上下文时也应给出非空说明）
        ack = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("192.0.2.10", "192.0.2.20", 6, tcp_seg(12345, 80, 50, 9, 0x10)))
        dns_q = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                      ipv4_pkt("192.0.2.10", "192.0.2.53", 17, udp_dgram(53000, 53, dns_query("www.example.com"))))
        dns_a = frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                      ipv4_pkt("192.0.2.53", "192.0.2.10", 17, udp_dgram(53, 53000, dns_answer("www.example.com", "93.184.216.34"))))
        http = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                     ipv4_pkt("192.0.2.10", "192.0.2.20", 6, tcp_seg(54321, 80, 1000, 1, 0x18, http_get("/hello", "www.example.com"))))
        arp = eth("ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01", 0x0806, arp_who_has("192.168.1.10", "192.168.1.1"))
        icmp = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                     ipv4_pkt("10.0.0.1", "10.0.0.2", 1, icmp_echo(8, 7, 9, b"ping")))
        # ICMP dest unreachable type 3 code 1
        unreach = struct.pack("!BBHHH", 3, 1, 0, 0, 0) + b"\x00" * 8
        unreach = unreach[:2] + struct.pack("!H", checksum(unreach)) + unreach[4:]
        icmp_un = frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                        ipv4_pkt("10.0.0.2", "10.0.0.1", 1, unreach))
        tls = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("192.0.2.10", "192.0.2.20", 6, tcp_seg(41000, 443, 1, 1, 0x18, tls_client_hello("example.com"))))
        self._open([ack, dns_q, dns_a, http, arp, icmp, icmp_un, tls])

        a_ack = self._detail(1)["analysis"]
        self.assertTrue(a_ack["summary"])
        self.assertTrue("ACK" in a_ack["summary"] or any("ACK" in (h.get("text") or "") for h in a_ack["hints"]))
        self.assertTrue("ACK" in self._concl_text(a_ack))

        a_dq = self._detail(2)["analysis"]
        self.assertIn("DNS", a_dq["summary"])
        self.assertIn("查询", a_dq["summary"])
        self.assertIn("www.example.com", a_dq["summary"])
        t_dq = self._concl_text(a_dq)
        self.assertIn("DNS 查询", t_dq)
        self.assertIn("www.example.com", t_dq)

        a_da = self._detail(3)["analysis"]
        self.assertIn("应答", a_da["summary"])
        self.assertIn("www.example.com", a_da["summary"])
        t_da = self._concl_text(a_da)
        self.assertIn("DNS 应答", t_da)
        self.assertIn("www.example.com", t_da)

        a_http = self._detail(4)["analysis"]
        self.assertIn("HTTP", a_http["summary"])
        self.assertIn("GET", a_http["summary"])
        self.assertIn("www.example.com", a_http["summary"])
        t_http = self._concl_text(a_http)
        self.assertIn("HTTP 请求", t_http)
        self.assertIn("GET", t_http)
        self.assertIn("www.example.com", t_http)

        a_arp = self._detail(5)["analysis"]
        self.assertIn("ARP", a_arp["summary"])
        self.assertTrue("请求" in a_arp["summary"] or "Who has" in (a_arp["summary"] + str(a_arp["points"])))
        self.assertIn("192.168.1.1", a_arp["summary"])
        t_arp = self._concl_text(a_arp)
        self.assertIn("ARP 请求", t_arp)
        self.assertIn("192.168.1.1", t_arp)

        a_icmp = self._detail(6)["analysis"]
        self.assertTrue("回显请求" in a_icmp["summary"] or "ping" in a_icmp["summary"].lower())
        t_icmp = self._concl_text(a_icmp)
        self.assertTrue("回显请求" in t_icmp or "ping" in t_icmp.lower())

        a_un = self._detail(7)["analysis"]
        self.assertIn("不可达", a_un["summary"])
        self.assertIn("不可达", self._concl_text(a_un))

        a_tls = self._detail(8)["analysis"]
        self.assertIn("TLS", a_tls["summary"])
        self.assertIn("example.com", a_tls["summary"])
        self.assertIn("不解密", a_tls["summary"])
        t_tls = self._concl_text(a_tls)
        self.assertIn("TLS ClientHello", t_tls)
        self.assertIn("example.com", t_tls)

        diag = session.diagnose()
        self.assertGreaterEqual(diag["count"], 8)
        titles = [c["title"] for c in diag["conclusions"]]
        self.assertTrue(any("HTTP" in t for t in titles))
        self.assertTrue(any("DNS" in t for t in titles))
        self.assertTrue(any("SNI" in t or "TLS" in t for t in titles))
        self.assertTrue(any("不可达" in t for t in titles))
        brief = session.deep_analyze_brief(no=4)
        self.assertIn("离线诊断", brief["text"])
        self.assertNotIn("raw_b64", brief["text"])
        self.assertGreater(brief["count"], 0)

    def test_rst_and_retransmit_in_diagnosis(self):
        syn = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.1.1.1", "10.1.1.2", 6, tcp_seg(2000, 22, 10, 0, 0x02)))
        rst = frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                    ipv4_pkt("10.1.1.2", "10.1.1.1", 6, tcp_seg(22, 2000, 0, 11, 0x14)))
        data = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                     ipv4_pkt("10.2.2.1", "10.2.2.2", 6, tcp_seg(3000, 80, 500, 1, 0x18, b"hello-world")))
        retr = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                     ipv4_pkt("10.2.2.1", "10.2.2.2", 6, tcp_seg(3000, 80, 500, 1, 0x18, b"hello-world")))
        self._open([syn, rst, data, retr])
        a_rst = self._detail(2)["analysis"]
        self.assertIn("RST", a_rst["summary"])
        self.assertIn("RST", self._concl_text(a_rst))
        a_re = self._detail(4)["analysis"]
        self.assertTrue(any("重传" in (h.get("text") or "") for h in a_re["hints"]) or "重传" in a_re["summary"])
        self.assertIn("重传", self._concl_text(a_re))
        diag = session.diagnose()
        titles = [c["title"] for c in diag["conclusions"]]
        self.assertTrue(any("重置" in t or "RST" in t for t in titles))
        self.assertTrue(any("重传" in t for t in titles))

    def test_packet_api_returns_conclusions(self):
        # /api/pcap/packet/<n> 返回 jsonify(ok=True, **pktcap.packet_detail(no))
        syn = frame("02:00:00:00:00:02", "02:00:00:00:00:01",
                    ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(40000, 443, 1000, 0, 0x02)))
        self._open([syn])
        import json
        payload = {"ok": True, **session.packet_detail(1)}
        # 模拟接口 JSON 序列化，保证 conclusions 能随响应发出
        d = json.loads(json.dumps(payload, ensure_ascii=False))
        self.assertTrue(d.get("ok"))
        self.assertIn("analysis", d)
        self.assertIn("conclusions", d["analysis"])
        cons = d["analysis"]["conclusions"]
        self.assertTrue(cons)
        self.assertTrue(cons[0].get("title"))
        self.assertTrue(cons[0].get("detail"))
        self.assertIn("SYN", (cons[0].get("title") or "") + (cons[0].get("detail") or ""))

    def test_udp_vxlan_not_tcp_flags_and_detailed_conclusions(self):
        # 与用户截图同类：UDP 10.145.11.162:33111 -> 10.145.32.22:4789
        payload = b"\x08" + b"\x00" * 7 + b"inner-frame-placeholder" + b"\x00" * 40
        vxlan = frame(
            "02:00:00:00:00:02", "02:00:00:00:00:01",
            ipv4_pkt("10.145.11.162", "10.145.32.22", 17, udp_dgram(33111, 4789, payload)),
        )
        other = frame(
            "02:00:00:00:00:02", "02:00:00:00:00:01",
            ipv4_pkt("10.145.11.162", "10.145.32.22", 17, udp_dgram(40000, 9999, b"hello-udp-payload")),
        )
        self._open([vxlan, other])

        a1 = self._detail(1)["analysis"]
        cons = a1["conclusions"]
        self.assertGreaterEqual(len(cons), 2, cons)
        blob = self._concl_text(a1)
        for bad in ("标志组合异常", "未置位任何常见标志", "TCP 标志", "三次握手", "纯 ACK"):
            self.assertNotIn(bad, blob)
        self.assertIn("UDP", blob)
        self.assertTrue("VXLAN" in blob or "4789" in blob, blob)
        self.assertIn("10.145.11.162", blob)
        self.assertIn("10.145.32.22", blob)
        for c in cons:
            self.assertGreaterEqual(len((c.get("detail") or "").strip()), 40, c)
            self.assertNotIn("…", c.get("detail") or "")
            self.assertFalse((c.get("detail") or "").endswith("..."))

        a2 = self._detail(2)["analysis"]
        cons2 = a2["conclusions"]
        self.assertGreaterEqual(len(cons2), 2, cons2)
        blob2 = self._concl_text(a2)
        self.assertNotIn("标志组合异常", blob2)
        self.assertNotIn("未置位任何常见标志", blob2)
        self.assertIn("UDP", blob2)
        for c in cons2:
            self.assertGreaterEqual(len((c.get("detail") or "").strip()), 40, c)

        diag = session.diagnose()
        titles = [c["title"] for c in diag["conclusions"]]
        self.assertIn("TCP 握手", titles)
        handshake = next(c for c in diag["conclusions"] if c["title"] == "TCP 握手")
        self.assertIn("没有识别到 TCP", handshake["detail"])
        all_diag = "\n".join(c.get("detail") or "" for c in diag["conclusions"])
        self.assertNotIn("已有确认或数据", all_diag)

        # TCP 数据报文仍应给出多条详细结论，而不是一句空话
        data = frame(
            "02:00:00:00:00:02", "02:00:00:00:00:01",
            ipv4_pkt("10.0.0.1", "10.0.0.2", 6, tcp_seg(40000, 80, 1000, 1, 0x18, b"hello-world-data")),
        )
        self._open([data])
        a3 = self._detail(1)["analysis"]
        cons3 = a3["conclusions"]
        self.assertGreaterEqual(len(cons3), 2, cons3)
        t3 = self._concl_text(a3)
        self.assertIn("携带有效载荷", t3)
        self.assertIn("10.0.0.1", t3)
        self.assertTrue("80" in t3 or "HTTP" in t3)
        payload_c = next(c for c in cons3 if c["title"] == "携带有效载荷")
        self.assertGreaterEqual(len(payload_c["detail"]), 40)
        self.assertNotEqual(payload_c["detail"].strip(), "这条报文携带有效载荷。")

    def tearDown(self):
        try:
            session.clear_packets()
        except Exception:
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
