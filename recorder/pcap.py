"""Binary pcap stream parser.

Reads the pcap stream tcpdump writes to stdout with `-w -`. Because `-w` is used,
tcpdump's protocol dissectors never run: this module sees raw bytes and decodes only
fixed-offset header fields. That removes tcpdump's most CVE-prone code from the path
and removes any dependence on its (version-unstable) text output format.

Handles both link types libpcap produces for `-i any`:
  LINKTYPE_LINUX_SLL  (113) - libpcap <= 1.9, no interface index
  LINKTYPE_LINUX_SLL2 (276) - libpcap >= 1.10, carries interface index
"""

import struct

LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8

IPPROTO_TCP = 6
IPPROTO_UDP = 17

# IPv6 extension headers that carry (next_header, hdr_ext_len) in their first 2 bytes.
_V6_EXT_HDRS = {0, 43, 60, 137, 139, 140}
_V6_FRAGMENT = 44

# Linux SLL packet types.
_PKTTYPE = {0: "in", 1: "in", 2: "in", 3: "other", 4: "out"}

_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),        # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": (">", 1000),        # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": ("<", 1),           # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": (">", 1),           # big-endian, nanoseconds
}


class PcapFormatError(Exception):
    pass


class Flow:
    """One observed packet, reduced to metadata. No payload is retained."""

    __slots__ = ("utc", "ifindex", "direction", "proto", "src", "sport", "dst", "dport")

    def __init__(self, utc, ifindex, direction, proto, src, sport, dst, dport):
        self.utc = utc
        self.ifindex = ifindex
        self.direction = direction
        self.proto = proto
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport

    def key(self, iface):
        return (iface, self.proto, self.src, self.sport, self.dst, self.dport)


def _read_exactly(stream, n):
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _ip_str(raw):
    if len(raw) == 4:
        return "%d.%d.%d.%d" % tuple(raw)
    # IPv6, RFC 5952 compressed form via the stdlib (no third-party dependency).
    import ipaddress

    return str(ipaddress.IPv6Address(bytes(raw)))


def _parse_l3(data, proto_eth):
    """Return (proto, src, sport, dst, dport) or None."""
    # Unwrap VLAN tags if the kernel did not strip them.
    guard = 0
    while proto_eth in (ETH_P_8021Q, ETH_P_8021AD) and guard < 2:
        if len(data) < 4:
            return None
        proto_eth = struct.unpack_from("!H", data, 2)[0]
        data = data[4:]
        guard += 1

    if proto_eth == ETH_P_IP:
        if len(data) < 20:
            return None
        vihl = data[0]
        if vihl >> 4 != 4:
            return None
        ihl = (vihl & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        proto = data[9]
        # Non-initial fragments carry no transport header.
        frag_off = struct.unpack_from("!H", data, 6)[0] & 0x1FFF
        src, dst = _ip_str(data[12:16]), _ip_str(data[16:20])
        payload = data[ihl:]
        if frag_off:
            return (proto, src, 0, dst, 0)
    elif proto_eth == ETH_P_IPV6:
        if len(data) < 40:
            return None
        proto = data[6]
        src, dst = _ip_str(data[8:24]), _ip_str(data[24:40])
        payload = data[40:]
        # Walk a bounded number of extension headers.
        for _ in range(8):
            if proto in _V6_EXT_HDRS:
                if len(payload) < 2:
                    return (proto, src, 0, dst, 0)
                nxt, ext_len = payload[0], (payload[1] + 1) * 8
                if len(payload) < ext_len:
                    return (proto, src, 0, dst, 0)
                proto, payload = nxt, payload[ext_len:]
            elif proto == _V6_FRAGMENT:
                if len(payload) < 8:
                    return (proto, src, 0, dst, 0)
                # Only the first fragment has the transport header.
                if struct.unpack_from("!H", payload, 2)[0] & 0xFFF8:
                    return (payload[0], src, 0, dst, 0)
                proto, payload = payload[0], payload[8:]
            else:
                break
    else:
        return None

    if proto in (IPPROTO_TCP, IPPROTO_UDP) and len(payload) >= 4:
        sport, dport = struct.unpack_from("!HH", payload, 0)
        return (proto, src, sport, dst, dport)
    return (proto, src, 0, dst, 0)


class PcapStream:
    """Iterate Flow objects from a pcap byte stream."""

    def __init__(self, stream):
        self.stream = stream
        header = _read_exactly(stream, 24)
        if header is None or header[:4] not in _MAGICS:
            raise PcapFormatError(
                "not a pcap stream (bad magic: %r)" % (header[:4] if header else b"")
            )
        self.endian, self.frac_divisor = _MAGICS[header[:4]]
        self.linktype = struct.unpack_from(self.endian + "I", header, 20)[0]
        if self.linktype not in (LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
            raise PcapFormatError(
                "unsupported link type %d (expected LINUX_SLL/SLL2 from -i any)"
                % self.linktype
            )
        self._rec = struct.Struct(self.endian + "IIII")

    def __iter__(self):
        read = _read_exactly
        while True:
            hdr = read(self.stream, 16)
            if hdr is None:
                return
            ts_sec, ts_frac, incl_len, _orig_len = self._rec.unpack(hdr)
            if incl_len > 262144:
                raise PcapFormatError("implausible record length %d" % incl_len)
            data = read(self.stream, incl_len)
            if data is None:
                return
            flow = self._decode(ts_sec, ts_frac, data)
            if flow is not None:
                yield flow

    def _decode(self, ts_sec, ts_frac, data):
        # SLL/SLL2 fields are network byte order regardless of pcap endianness.
        if self.linktype == LINKTYPE_LINUX_SLL2:
            if len(data) < 20:
                return None
            proto_eth, _resv, ifindex = struct.unpack_from("!HHI", data, 0)
            pkttype = data[10]
            body = data[20:]
        else:
            if len(data) < 16:
                return None
            pkttype = struct.unpack_from("!H", data, 0)[0]
            proto_eth = struct.unpack_from("!H", data, 14)[0]
            ifindex = 0  # SLL carries no interface index
            body = data[16:]

        parsed = _parse_l3(body, proto_eth)
        if parsed is None:
            return None
        proto, src, sport, dst, dport = parsed
        return Flow(
            utc=ts_sec + (ts_frac // self.frac_divisor) / 1_000_000.0,
            ifindex=ifindex,
            direction=_PKTTYPE.get(pkttype, "?"),
            proto=proto,
            src=src,
            sport=sport,
            dst=dst,
            dport=dport,
        )
