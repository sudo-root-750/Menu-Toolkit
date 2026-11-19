import ipaddress
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_HOSTS = 1024  # safety limit for one scan


def ping_once(ip, timeout_ms=1000):
    """Ping one host once. Returns (ip, is_alive, response_ms)."""
    if platform.system().lower() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    start = time.perf_counter()
    try:
        result = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000) + 2,
        )
    except subprocess.TimeoutExpired:
        return ip, False, 0
    elapsed = (time.perf_counter() - start) * 1000
    return ip, result.returncode == 0, elapsed


def resolve_name(ip):
    """Try to find the hostname of an IP (reverse DNS)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "-"


def get_hosts(cidr):
    """Return the list of host IPs (as strings) for a CIDR like 192.168.1.0/24."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        raise ValueError("Only IPv4 is supported")
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > MAX_HOSTS:
        raise ValueError(f"Too many hosts ({len(hosts)}). Max is {MAX_HOSTS} (use /22 or smaller).")
    return hosts


def get_local_network():
    """Guess the local /24 network, e.g. '192.168.1.0/24'."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        ip = sock.getsockname()[0]
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except OSError:
        return ""
    finally:
        sock.close()


def ping_sweep():
    """Interactive ping sweep (to be called from the menu)."""
    default = get_local_network()
    prompt = f"Enter network (e.g. 192.168.1.0/24) [Enter = {default}]: " if default \
        else "Enter network (e.g. 192.168.1.0/24): "
    cidr = input(prompt).strip() or default

    try:
        hosts = get_hosts(cidr)
    except ValueError as e:
        print(f"[!] {e}")
        return

    print(f"\nScanning {len(hosts)} hosts in {cidr} ...")
    start = time.time()
    alive = []

    try:
        with ThreadPoolExecutor(max_workers=100) as pool:
            futures = [pool.submit(ping_once, ip) for ip in hosts]
            for f in as_completed(futures):
                ip, is_alive, ms = f.result()
                if is_alive:
                    alive.append((ip, ms))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")

    elapsed = time.time() - start
    alive.sort(key=lambda x: ipaddress.ip_address(x[0]))

    if not alive:
        print("No live hosts found (hosts may block ping).")
    else:
        print(f"\n{'IP ADDRESS':<18}{'TIME':<10}HOSTNAME")
        print("-" * 55)
        for ip, ms in alive:
            print(f"{ip:<18}{ms:<10.0f}{resolve_name(ip)}")

    print(f"\nLive hosts: {len(alive)} / {len(hosts)} | Done in {elapsed:.2f} seconds")