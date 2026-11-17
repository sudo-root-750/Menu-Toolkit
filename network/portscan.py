import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Most common ports (used when the user presses Enter)
TOP_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443,
]
TOP_UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 1900, 5353,
]

# Protocol-specific UDP probes (many UDP services only answer a valid request)
UDP_PROBES = {
    # DNS query for google.com
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x06google\x03com\x00\x00\x01\x00\x01",
    # NTP client request
    123: b"\x1b" + 47 * b"\x00",
}


def parse_ports(spec):
    """Convert '1-1024', '22,80,443' or '1-100,443' into a sorted list of ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    if not ports or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("Port numbers must be between 1 and 65535")
    return sorted(ports)


def check_tcp(ip, port, timeout):
    """Return (port, state, banner). State: open / closed / filtered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port, "open", grab_banner(sock)
        # 111 (Linux) / 10061 (Windows) / 61 (macOS): connection refused
        if result in (111, 10061, 61):
            return port, "closed", ""
        return port, "filtered", ""
    except OSError:
        return port, "filtered", ""
    finally:
        sock.close()


def check_udp(ip, port, timeout):
    """
    Return (port, state, banner). State: open / closed / open|filtered.
    - Got a reply            -> open
    - ICMP port unreachable  -> closed
    - No reply at all        -> open|filtered (UDP cannot tell the difference)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))  # needed to receive ICMP errors
        sock.send(UDP_PROBES.get(port, b"\x00"))
        data = sock.recv(1024)
        return port, "open", f"{len(data)} bytes reply"
    except socket.timeout:
        return port, "open|filtered", ""
    except ConnectionError:  # ICMP port unreachable (Linux / Windows)
        return port, "closed", ""
    except OSError:
        return port, "open|filtered", ""
    finally:
        sock.close()


def grab_banner(sock):
    """Try to read a short service banner from an open TCP port."""
    try:
        sock.settimeout(0.5)
        data = sock.recv(100)
        return data.decode(errors="ignore").strip().split("\n")[0][:40]
    except OSError:
        return ""


def service_name(port, protocol):
    """Return the common service name for a port (e.g. 80 -> http)."""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        return "unknown"


def ask_protocol():
    """Ask the user which protocol to scan. Returns 'tcp', 'udp' or None."""
    while True:
        choice = input("Scan type: \n > 1.TCP \n > 2.UDP \n > 0.back \n>>>").strip()
        match choice:
            case "1":
                return "tcp"
            case "2":
                return "udp"
            case "0":
                return None
            case _:
                print("Invalid choice. Try '1', '2' or '0'.")


def portscan():
    """Interactive nmap-style port scanner (TCP or UDP), called from the menu."""
    protocol = ask_protocol()
    if protocol is None:
        return

    default_ports = TOP_TCP_PORTS if protocol == "tcp" else TOP_UDP_PORTS
    check = check_tcp if protocol == "tcp" else check_udp
    timeout = 1.0 if protocol == "tcp" else 2.0

    target = input("Enter IP or Domain: ").strip()
    spec = input("Ports [Enter = top common ports, or e.g. 1-1024 / 22,80,443]: ").strip()

    # Resolve target and parse ports
    try:
        ip = socket.gethostbyname(target)
        ports = parse_ports(spec) if spec else default_ports
    except socket.gaierror:
        print(f"[!] Failed to resolve '{target}'")
        return
    except ValueError as e:
        print(f"[!] Invalid ports: {e}")
        return

    # Header (nmap style)
    print(f"\nStarting {protocol.upper()} scan at {time.strftime('%Y-%m-%d %H:%M:%S')}")
    if ip != target:
        print(f"Scan report for {target} ({ip})")
    else:
        print(f"Scan report for {ip}")

    start = time.time()
    results = {}

    try:
        with ThreadPoolExecutor(max_workers=100) as pool:
            futures = [pool.submit(check, ip, p, timeout) for p in ports]
            for f in as_completed(futures):
                port, state, info = f.result()
                results[port] = (state, info)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")

    elapsed = time.time() - start

    # Count states
    counts = {}
    for state, _ in results.values():
        counts[state] = counts.get(state, 0) + 1

    # Which states are shown in the table
    shown_states = ("open",) if protocol == "tcp" else ("open", "open|filtered")
    shown_n = sum(counts.get(s, 0) for s in shown_states)
    hidden = sum(n for s, n in counts.items() if s not in shown_states)

    # Host status
    if counts.get("open") or counts.get("closed"):
        print("Host is up.")
    elif protocol == "udp":
        print("No response from any port (host may be down or UDP is filtered).")
    else:
        print("Host seems down or all ports are filtered.")

    # Summary of hidden ports (like nmap)
    if hidden:
        hidden_states = {s: n for s, n in counts.items() if s not in shown_states}
        hidden_state = max(hidden_states, key=hidden_states.get)
        print(f"Not shown: {hidden} {hidden_state} {protocol} ports\n")

    # Table of ports
    if shown_n:
        print(f"{'PORT':<12}{'STATE':<15}{'SERVICE':<14}INFO")
        for port in sorted(results):
            state, info = results[port]
            if state in shown_states:
                label = f"{port}/{protocol}"
                print(f"{label:<12}{state:<15}{service_name(port, protocol):<14}{info}")
    else:
        print(f"No open {protocol.upper()} ports found.")

    print(f"\nScan done: 1 IP address scanned in {elapsed:.2f} seconds")