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
        # libpcap load must not throw
        lib, path, err = core.pktcap.libpcap.load()
        self.assertTrue(lib is None or lib is not None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
