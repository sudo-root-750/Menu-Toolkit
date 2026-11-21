"""
A small DNS client built on `socket` (no dnspython needed).
Supports A, AAAA, CNAME, NS, MX, TXT, SOA, PTR and CAA over UDP with TCP fallback.
"""
import ipaddress
import random
import socket
import struct
import time

from network.common import IS_MAC, IS_WINDOWS, run_cmd

DNS_PORT = 53
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
          "TXT": 16, "AAAA": 28, "CAA": 257}
TYPE_NAMES = {number: name for name, number in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

PUBLIC_RESOLVERS = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
    "OpenDNS": "208.67.222.222",
}

_system_dns_cache = []


class DNSError(Exception):
    """Raised for timeouts, network errors and malformed answers."""


# ---------- Building a query ----------

def encode_name(name):
    name = name.rstrip(".")
    out = b""
    if name:
        for label in name.split("."):
            raw = label.encode("ascii") if label.isascii() else label.encode("idna")
            if not 1 <= len(raw) <= 63:
                raise DNSError(f"Invalid name: '{name}'")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(name, qtype):
    """Return (query_bytes, query_id). Adds an EDNS0 record for larger UDP answers."""
    query_id = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 1)
    question = encode_name(name) + struct.pack(">HH", qtype, 1)
    edns = b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0)
    return header + question + edns, query_id


# ---------- Reading an answer ----------

def parse_name(data, offset):
    """Read a (possibly compressed) name. Returns (name, offset_after_name)."""
    labels, end, jumped, hops = [], offset, False, 0
    while True:
        if offset >= len(data):
            raise DNSError("Malformed answer")
        length = data[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSError("Malformed answer")
            if not jumped:
                end = offset + 2
            jumped = True
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            hops += 1
            if hops > 50:
                raise DNSError("Compression loop in answer")
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), end


def parse_rdata(rtype, data, offset, length):
    """Turn the raw data of one record into readable text."""
    end = offset + length
    if rtype == 1 and length == 4:
        return socket.inet_ntoa(data[offset:end])
    if rtype == 28 and length == 16:
        return socket.inet_ntop(socket.AF_INET6, data[offset:end])
    if rtype in (2, 5, 12):
        return parse_name(data, offset)[0]
    if rtype == 15:
        preference = struct.unpack(">H", data[offset:offset + 2])[0]
        return f"{preference} {parse_name(data, offset + 2)[0]}"
    if rtype == 16:
        parts, pos = [], offset
        while pos < end:
            size = data[pos]
            parts.append(data[pos + 1:pos + 1 + size].decode("utf-8", "replace"))
            pos += 1 + size
        return "".join(parts)
    if rtype == 6:
        mname, pos = parse_name(data, offset)
        rname, pos = parse_name(data, pos)
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[pos:pos + 20])
        return f"{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} min={minimum}"
    if rtype == 257 and length >= 2:
        flags, tag_length = data[offset], data[offset + 1]
        tag = data[offset + 2:offset + 2 + tag_length].decode("ascii", "replace")
        value = data[offset + 2 + tag_length:end].decode("ascii", "replace")
        return f'{flags} {tag} "{value}"'
    return data[offset:end].hex()


def parse_response(data, query_id):
    """Return (rcode_name, truncated, records)."""
    if len(data) < 12:
        raise DNSError("Answer too short")
    rid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if rid != query_id:
        raise DNSError("Answer does not match the question")
    rcode = RCODES.get(flags & 0xF, f"RCODE{flags & 0xF}")
    truncated = bool(flags & 0x0200)

    offset = 12
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4

    records = []
    for _ in range(ancount):
        name, offset = parse_name(data, offset)
        if offset + 10 > len(data):
            raise DNSError("Malformed answer")
        rtype, _, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        records.append({
            "name": name,
            "type": TYPE_NAMES.get(rtype, f"TYPE{rtype}"),
            "ttl": ttl,
            "data": parse_rdata(rtype, data, offset, rdlength),
        })
        offset += rdlength
    return rcode, truncated, records


# ---------- Sending ----------

def _family(server):
    return socket.AF_INET6 if ipaddress.ip_address(server).version == 6 else socket.AF_INET


def _ask_udp(query, query_id, server, timeout):
    sock = socket.socket(_family(server), socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, DNS_PORT))
        deadline = time.time() + timeout
        while True:
            sock.settimeout(max(0.05, deadline - time.time()))
            data, sender = sock.recvfrom(4096)
            if sender[0] == server and len(data) >= 2 and struct.unpack(">H", data[:2])[0] == query_id:
                return data
            if time.time() > deadline:
                raise socket.timeout()
    finally:
        sock.close()


def _ask_tcp(query, server, timeout):
    with socket.create_connection((server, DNS_PORT), timeout=timeout) as sock:
        sock.sendall(struct.pack(">H", len(query)) + query)
        header = b""
        while len(header) < 2:
            chunk = sock.recv(2 - len(header))
            if not chunk:
                raise DNSError("Connection closed")
            header += chunk
        size = struct.unpack(">H", header)[0]
        data = b""
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                raise DNSError("Connection closed")
            data += chunk
        return data


def query(name, rtype, server, timeout=3.0, retries=1):
    """
    Ask one DNS server. Returns (rcode_name, records).
    rcode_name is e.g. 'NOERROR' or 'NXDOMAIN'. Raises DNSError on failure.
    """
    qtype = QTYPES[rtype]
    packet, query_id = build_query(name, qtype)
    last_error = "timeout"
    for _ in range(retries + 1):
        try:
            data = _ask_udp(packet, query_id, server, timeout)
            rcode, truncated, records = parse_response(data, query_id)
            if truncated:
                rcode, _, records = parse_response(_ask_tcp(packet, server, timeout), query_id)
            return rcode, records
        except socket.timeout:
            last_error = "timeout"
        except (OSError, struct.error) as error:
            last_error = str(error)
    raise DNSError(last_error)


# ---------- System resolvers and convenience ----------

def get_system_dns():
    """DNS servers configured on this computer (falls back to Cloudflare / Google)."""
    if _system_dns_cache:
        return list(_system_dns_cache)

    found = []
    if IS_WINDOWS:
        out = run_cmd(["powershell", "-NoProfile", "-Command",
                       "Get-DnsClientServerAddress -AddressFamily IPv4 | "
                       "ForEach-Object { $_.ServerAddresses }"], timeout=20)
        found = (out or "").split()
    elif IS_MAC:
        out = run_cmd(["scutil", "--dns"]) or ""
        found = [line.split(":", 1)[1].strip() for line in out.splitlines()
                 if line.strip().startswith("nameserver[")]
    else:
        try:
            with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as f:
                found = [line.split()[1] for line in f
                         if line.startswith("nameserver") and len(line.split()) > 1]
        except OSError:
            pass

    servers = []
    for item in found:
        try:
            ip = str(ipaddress.ip_address(item.split("%")[0]))
        except ValueError:
            continue
        if ip not in servers:
            servers.append(ip)
    _system_dns_cache.extend(servers or ["1.1.1.1", "8.8.8.8"])
    return list(_system_dns_cache)


def resolve(name, rtype, server=None, timeout=3.0):
    """Query one server, or the system servers in order. Returns (rcode, records, server_used)."""
    servers = [server] if server else get_system_dns()
    last_error = DNSError("no DNS server available")
    for candidate in servers:
        try:
            rcode, records = query(name, rtype, candidate, timeout)
            return rcode, records, candidate
        except DNSError as error:
            last_error = error
    raise last_error


def reverse_name(ip):
    return ipaddress.ip_address(ip).reverse_pointer
