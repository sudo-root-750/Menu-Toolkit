"""TCP Port Check: quickly test one or more ports on a host (host:port)."""
import re
import socket
import time

from network.common import ask, ask_int, clean_host, stats

MAX_PORTS = 100


def parse_ports(text):
    """'80,443,8000-8003' -> [80, 443, 8000, ...]. Raises ValueError if invalid."""
    ports = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = (int(x) for x in part.split("-", 1))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    if not ports or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("Ports must be between 1 and 65535")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"Too many ports (max {MAX_PORTS}); use the Port Scan tool for big ranges")
    return sorted(ports)


def split_target(raw):
    """'example.com:443', 'https://example.com' or '[::1]:80' -> (host, [ports])."""
    raw = raw.strip()
    default_ports = []
    if "://" in raw:
        scheme, raw = raw.split("://", 1)
        default_ports = {"https": [443], "http": [80]}.get(scheme.lower(), [])
    raw = re.split(r"[/?#]", raw, maxsplit=1)[0]

    ports_text = ""
    if raw.startswith("["):
        host_part, _, rest = raw.partition("]")
        host_part, ports_text = host_part[1:], rest.lstrip(":")
    elif raw.count(":") == 1:
        host_part, ports_text = raw.split(":", 1)
    else:
        host_part = raw

    host = clean_host(host_part)
    return host, (parse_ports(ports_text) if ports_text else default_ports)


def read_banner(sock):
    """Read a short greeting if the service sends one (SSH, SMTP, FTP, ...)."""
    try:
        sock.settimeout(0.6)
        data = sock.recv(120)
        return data.decode(errors="ignore").strip().splitlines()[0][:60] if data else ""
    except (OSError, IndexError):
        return ""


def check_once(host, port, timeout):
    """Return (state, milliseconds, ip_address, banner)."""
    started = time.perf_counter()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return "closed", (time.perf_counter() - started) * 1000, "", ""
    except socket.gaierror:
        return "unresolved", 0.0, "", ""
    except (socket.timeout, TimeoutError):
        return "timeout", timeout * 1000, "", ""
    except OSError as error:
        return f"error ({error.strerror or error})", 0.0, "", ""
    elapsed = (time.perf_counter() - started) * 1000
    address = sock.getpeername()[0]
    banner = read_banner(sock)
    sock.close()
    return "open", elapsed, address, banner


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "-"


def tcp_check():
    """Interactive TCP port check (to be called from the menu)."""
    raw = ask("Enter host:port (e.g. example.com:443 or example.com:80,443): ")
    try:
        host, ports = split_target(raw)
    except ValueError as error:
        print(f"[!] {error}")
        return
    if not host:
        print("[!] Invalid host.")
        return
    if not ports:
        try:
            ports = parse_ports(ask("Port(s) (e.g. 443 or 80,443,8000-8003): "))
        except ValueError as error:
            print(f"[!] Invalid ports: {error}")
            return

    attempts = ask_int("Attempts per open port (for timing)", 3, 1, 20) if len(ports) == 1 else 1
    if attempts is None:
        return

    print(f"\nChecking {host} ...\n")
    print(f"{'PORT':<8}{'STATE':<14}{'TIME':<12}{'SERVICE':<12}{'ADDRESS':<18}BANNER")
    print("-" * 78)
    for port in ports:
        state, first_ms, address, banner = check_once(host, port, 3.0)
        times = [first_ms]
        if state == "open":
            for _ in range(attempts - 1):
                again, ms, _, _ = check_once(host, port, 3.0)
                if again == "open":
                    times.append(ms)
        shown_time = f"{first_ms:.0f} ms" if state in ("open", "closed") else "-"
        print(f"{port:<8}{state:<14}{shown_time:<12}{service_name(port):<12}{address:<18}{banner}")
        if state == "open" and len(times) > 1:
            low, average, high, jitter = stats(times)
            print(f"        {len(times)} attempts: min {low:.0f} | avg {average:.0f} | "
                  f"max {high:.0f} ms | jitter {jitter:.0f} ms")
        if state == "unresolved":
            print(f"\n[!] Could not resolve '{host}'.")
            return

    print("\nopen = something accepts connections | closed = reachable but nothing listens | "
          "timeout = no answer (often a firewall)")
