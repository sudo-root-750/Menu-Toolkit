"""
Packet Sniffer (educational): watch the headers of packets on THIS computer's network card.
Only headers are decoded (addresses, ports, protocol, size). Payload contents are never shown.
Needs administrator / root rights.
"""
import ipaddress
import socket
import struct
import sys
import time

from network.common import IS_MAC, IS_WINDOWS, ask, ask_int, ask_yes

TCP_FLAGS = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG")]
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 41: "IPv6", 47: "GRE", 50: "ESP"}


def parse_ipv4(packet):
    """
    Decode an IPv4 packet (starting at the IP header).
    Returns a dict with src, dst, protocol, length, and sport/dport/flags when known; None if invalid.
    """
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_len = (packet[0] & 0x0F) * 4
    if header_len < 20 or len(packet) < header_len:
        return None
    total_length = struct.unpack(">H", packet[2:4])[0]
    proto = packet[9]
    info = {
        "src": socket.inet_ntoa(packet[12:16]),
        "dst": socket.inet_ntoa(packet[16:20]),
        "proto": PROTOCOLS.get(proto, str(proto)),
        "length": total_length,
        "sport": None, "dport": None, "flags": "",
    }
    payload = packet[header_len:]
    if proto in (6, 17) and len(payload) >= 4:
        info["sport"], info["dport"] = struct.unpack(">HH", payload[:4])
        if proto == 6 and len(payload) >= 14:
            info["flags"] = "+".join(name for bit, name in TCP_FLAGS if payload[13] & bit)
    elif proto == 1 and len(payload) >= 2:
        info["flags"] = {0: "echo-reply", 3: "unreachable", 8: "echo-request", 11: "ttl-exceeded"}.get(payload[0], f"type {payload[0]}")
    return info


def parse_ethernet(frame):
    """Decode an Ethernet frame; only IPv4 is analysed. Returns an info dict or None."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    if ethertype == 0x8100 and len(frame) >= 18:  # VLAN tag
        ethertype, frame = struct.unpack(">H", frame[16:18])[0], frame[4:]
    if ethertype == 0x0806:
        return {"src": ":".join(f"{b:02x}" for b in frame[6:12]), "dst": ":".join(f"{b:02x}" for b in frame[:6]),
                "proto": "ARP", "length": len(frame), "sport": None, "dport": None, "flags": ""}
    if ethertype != 0x0800:
        return None
    return parse_ipv4(frame[14:])


def matches(info, protocol, host, port):
    if protocol and info["proto"] != protocol:
        return False
    if host and host not in (info["src"], info["dst"]):
        return False
    if port and port not in (info["sport"], info["dport"]):
        return False
    return True


def open_sniffer(local_ip):
    """Return (socket, has_ethernet_header). Raises PermissionError without admin rights."""
    if IS_WINDOWS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((local_ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return sock, False
    if hasattr(socket, "AF_PACKET"):  # Linux
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)), True
    raise OSError("Raw packet capture is not supported on this system without extra libraries (try scapy).")


def packet_sniffer():
    """Interactive packet viewer (to be called from the menu)."""
    from network.common import get_local_ip

    print("[i] Educational tool: it shows headers only (who talks to whom), never the content.")
    print("[i] Use it only on your own computer and network. It needs administrator/root rights.\n")
    if not ask_yes("Continue?", True):
        return

    protocol = ask("Protocol filter (TCP / UDP / ICMP / ARP) [Enter = all]: ").upper()
    if protocol and protocol not in ("TCP", "UDP", "ICMP", "ARP"):
        print("[!] Unknown protocol.")
        return
    host = ask("Only show traffic of this IP [Enter = all]: ")
    if host:
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            print("[!] Invalid IP.")
            return
    port_text = ask("Only show this port [Enter = all]: ")
    port = int(port_text) if port_text.isdigit() and 1 <= int(port_text) <= 65535 else None
    if port_text and port is None:
        print("[!] Invalid port.")
        return
    limit = ask_int("Stop after how many packets (1-5000)", 100, 1, 5000)
    if limit is None:
        return

    local_ip = get_local_ip() or "0.0.0.0"
    try:
        sock, ethernet = open_sniffer(local_ip)
    except PermissionError:
        print("[!] Permission denied. Run the program as administrator (Windows) or with sudo (Linux).")
        return
    except OSError as error:
        print(f"[!] Could not start capturing: {error}")
        return

    sock.settimeout(1.0)
    counts, shown = {}, 0
    print(f"\n{'TIME':<10}{'PROTO':<6}{'SOURCE':<24}{'DESTINATION':<24}{'SIZE':<7}INFO")
    print("-" * 85)
    try:
        while shown < limit:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            info = parse_ethernet(data) if ethernet else parse_ipv4(data)
            if not info or not matches(info, protocol, host, port):
                continue
            src = f"{info['src']}:{info['sport']}" if info["sport"] else info["src"]
            dst = f"{info['dst']}:{info['dport']}" if info["dport"] else info["dst"]
            print(f"{time.strftime('%H:%M:%S'):<10}{info['proto']:<6}{src[:23]:<24}{dst[:23]:<24}"
                  f"{info['length']:<7}{info['flags']}")
            counts[info["proto"]] = counts.get(info["proto"], 0) + 1
            shown += 1
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
    finally:
        if IS_WINDOWS:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        sock.close()

    if counts:
        print("\nSummary: " + ", ".join(f"{name}: {n}" for name, n in sorted(counts.items(), key=lambda x: -x[1])))
    else:
        print("\nNo matching packets were captured.")
