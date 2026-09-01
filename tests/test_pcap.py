"""Parser tests over synthetic byte sequences - no root, no network required."""

import struct
import unittest
from io import BytesIO

from recorder.pcap import (
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    PcapFormatError,
    PcapStream,
)


def pcap_header(linktype, endian="<"):
    magic = b"\xd4\xc3\xb2\xa1" if endian == "<" else b"\xa1\xb2\xc3\xd4"
    return magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, 262144, linktype)


def record(payload, ts=1_700_000_000, endian="<"):
    return struct.pack(endian + "IIII", ts, 0, len(payload), len(payload)) + payload


def sll2(proto, ifindex, pkttype, body):
    return struct.pack("!HHIHBB", proto, 0, ifindex, 1, pkttype, 6) + b"\0" * 8 + body


def sll(proto, pkttype, body):
    return struct.pack("!HHH", pkttype, 1, 6) + b"\0" * 8 + struct.pack("!H", proto) + body


def ipv4(src, dst, proto=6, sport=1234, dport=443, frag_off=0):
    hdr = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 40, 0, frag_off, 64, proto, 0,
        bytes(int(o) for o in src.split(".")), bytes(int(o) for o in dst.split(".")),
    )
    return hdr + struct.pack("!HH", sport, dport) + b"\0" * 16


def ipv6(src, dst, proto=6, sport=1234, dport=443):
    import ipaddress
    hdr = struct.pack("!IHBB", 6 << 28, 20, proto, 64)
    hdr += ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
    return hdr + struct.pack("!HH", sport, dport) + b"\0" * 16


class TestPcapStream(unittest.TestCase):
    def parse(self, linktype, records):
        blob = pcap_header(linktype) + b"".join(record(r) for r in records)
        return list(PcapStream(BytesIO(blob)))

    def test_sll2_ipv4_carries_interface_and_direction(self):
        flows = self.parse(
            LINKTYPE_LINUX_SLL2,
            [sll2(0x0800, 7, 4, ipv4("10.21.21.12", "203.0.113.42", dport=34567))],
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].ifindex, 7)
        self.assertEqual(flows[0].direction, "out")
        self.assertEqual(flows[0].src, "10.21.21.12")
        self.assertEqual(flows[0].dst, "203.0.113.42")
        self.assertEqual(flows[0].dport, 34567)

    def test_sll_v1_has_no_interface_index(self):
        """libpcap <= 1.9 emits SLL; a parser assuming SLL2 records nothing."""
        flows = self.parse(
            LINKTYPE_LINUX_SLL, [sll(0x0800, 0, ipv4("192.168.1.50", "203.0.113.42"))]
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].ifindex, 0)
        self.assertEqual(flows[0].direction, "in")
        self.assertEqual(flows[0].src, "192.168.1.50")

    def test_ipv6_is_parsed(self):
        flows = self.parse(
            LINKTYPE_LINUX_SLL2,
            [sll2(0x86DD, 3, 4, ipv6("2001:db8::1", "2001:db8::2", dport=9735))],
        )
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].src, "2001:db8::1")
        self.assertEqual(flows[0].dport, 9735)

    def test_vlan_tag_is_unwrapped(self):
        tagged = struct.pack("!HH", 0x0064, 0x0800) + ipv4("10.0.0.1", "203.0.113.9")
        flows = self.parse(LINKTYPE_LINUX_SLL2, [sll2(0x8100, 3, 4, tagged)])
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].dst, "203.0.113.9")

    def test_non_initial_fragment_has_no_ports(self):
        flows = self.parse(
            LINKTYPE_LINUX_SLL2,
            [sll2(0x0800, 3, 4, ipv4("10.0.0.1", "203.0.113.9", frag_off=185))],
        )
        self.assertEqual(flows[0].sport, 0)
        self.assertEqual(flows[0].dport, 0)

    def test_non_ip_ethertype_ignored(self):
        self.assertEqual(self.parse(LINKTYPE_LINUX_SLL2, [sll2(0x0806, 3, 4, b"\0" * 28)]), [])

    def test_truncated_stream_stops_cleanly(self):
        blob = pcap_header(LINKTYPE_LINUX_SLL2) + b"\x01\x02\x03"
        self.assertEqual(list(PcapStream(BytesIO(blob))), [])

    def test_rejects_ethernet_linktype(self):
        with self.assertRaises(PcapFormatError):
            PcapStream(BytesIO(pcap_header(1)))

    def test_rejects_non_pcap(self):
        with self.assertRaises(PcapFormatError):
            PcapStream(BytesIO(b"not a pcap stream at all...."))


if __name__ == "__main__":
    unittest.main()
