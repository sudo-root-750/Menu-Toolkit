"""Local Network Info: IP addresses, gateway, DNS, MAC and interfaces of THIS computer."""
import re
import socket

from network.common import (IS_MAC, IS_WINDOWS, format_bytes, get_local_ip,
                            run_cmd)
from network.dns_client import get_system_dns

try:
    import psutil
except ImportError:
    psutil = None


def get_gateway():
    """Default gateway IPv4 address, or '' if it cannot be found."""
    if IS_WINDOWS:
        out = run_cmd(["powershell", "-NoProfile", "-Command",
                       "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | "
                       "Select-Object -First 1).NextHop"], timeout=20)
        if out and re.search(r"\d+\.\d+\.\d+\.\d+", out):
            return re.search(r"\d+\.\d+\.\d+\.\d+", out).group(0)
        out = run_cmd(["route", "print", "0.0.0.0"]) or ""
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
        return ""
    if IS_MAC:
        out = run_cmd(["route", "-n", "get", "default"]) or ""
        match = re.search(r"gateway:\s*(\S+)", out)
        return match.group(1) if match else ""
    try:
        with open("/proc/net/route", encoding="ascii") as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if len(fields) > 2 and fields[1] == "00000000" and int(fields[3], 16) & 2:
                    raw = bytes.fromhex(fields[2])[::-1]  # stored little-endian
                    return socket.inet_ntoa(raw)
    except (OSError, ValueError):
        pass
    out = run_cmd(["ip", "route", "show", "default"]) or ""
    match = re.search(r"default via (\S+)", out)
    return match.group(1) if match else ""


def interface_rows():
    """Return a list of dicts describing every interface (needs psutil)."""
    rows = []
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    for name, addresses in psutil.net_if_addrs().items():
        row = {"name": name, "ipv4": [], "ipv6": [], "mac": "", "mask": "",
               "up": stats[name].isup if name in stats else False,
               "speed": stats[name].speed if name in stats else 0,
               "mtu": stats[name].mtu if name in stats else 0,
               "sent": counters[name].bytes_sent if name in counters else 0,
               "recv": counters[name].bytes_recv if name in counters else 0}
        for addr in addresses:
            if addr.family == socket.AF_INET:
                row["ipv4"].append(addr.address)
                row["mask"] = addr.netmask or ""
            elif addr.family == socket.AF_INET6:
                row["ipv6"].append(addr.address.split("%")[0])
            elif getattr(psutil, "AF_LINK", None) is not None and addr.family == psutil.AF_LINK:
                row["mac"] = addr.address.replace("-", ":").lower()
        rows.append(row)
    return rows


def local_info():
    """Show network information of this computer (to be called from the menu)."""
    print("\n=== This computer ===")
    print(f"{'Hostname':<14}: {socket.gethostname()}")
    print(f"{'Main local IP':<14}: {get_local_ip() or 'not connected'}")
    print(f"{'Gateway':<14}: {get_gateway() or 'not found'}")
    print(f"{'DNS servers':<14}: {', '.join(get_system_dns())}")

    if psutil is None:
        print("\n[i] Install psutil for details about every interface: pip install psutil")
        return

    rows = [r for r in interface_rows() if r["ipv4"] or r["ipv6"]]
    rows.sort(key=lambda r: (not r["up"], r["name"].lower()))
    print("\n=== Network interfaces ===")
    for row in rows:
        state = "UP" if row["up"] else "down"
        print(f"\n{row['name']}  [{state}]")
        if row["mac"]:
            print(f"  MAC       : {row['mac']}")
        for ip in row["ipv4"]:
            print(f"  IPv4      : {ip}" + (f"  mask {row['mask']}" if row["mask"] else ""))
        for ip in row["ipv6"][:2]:
            print(f"  IPv6      : {ip}")
        details = []
        if row["speed"]:
            details.append(f"link speed {row['speed']} Mbps")
        if row["mtu"]:
            details.append(f"MTU {row['mtu']}")
        if details:
            print(f"  Link      : {', '.join(details)}")
        print(f"  Traffic   : sent {format_bytes(row['sent'])}, received {format_bytes(row['recv'])}")
    print("\n[i] 169.254.x.x means the computer could not get an address from the router (DHCP).")
