import os
import platform
import shutil
import socket
import time

# psutil is optional: without it, some sections are skipped
try:
    import psutil
except ImportError:
    psutil = None


def format_bytes(size):
    """Convert bytes to a readable string (e.g. 8589934592 -> 8.00 GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def format_duration(seconds):
    """Convert seconds to 'Xd Xh Xm'."""
    seconds = int(seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    return f"{days}d {hours}h {minutes}m"


def print_title(title):
    print(f"\n=== {title} ===")


def print_row(label, value):
    print(f"{label:<18}: {value}")


def show_os():
    print_title("Operating System")
    print_row("System", f"{platform.system()} {platform.release()}")
    print_row("Version", platform.version())
    print_row("Architecture", platform.machine())
    print_row("Hostname", socket.gethostname())
    print_row("Python", platform.python_version())
    if psutil:
        uptime = time.time() - psutil.boot_time()
        print_row("Uptime", format_duration(uptime))


def show_cpu():
    print_title("CPU")
    print_row("Processor", platform.processor() or "N/A")
    print_row("Logical cores", os.cpu_count())
    if psutil:
        print_row("Physical cores", psutil.cpu_count(logical=False))
        freq = psutil.cpu_freq()
        if freq:
            print_row("Frequency", f"{freq.current:.0f} MHz")
        print_row("Usage", f"{psutil.cpu_percent(interval=1)} %")


def show_memory():
    print_title("Memory")
    if not psutil:
        print("psutil is not installed (pip install psutil)")
        return
    ram = psutil.virtual_memory()
    print_row("Total RAM", format_bytes(ram.total))
    print_row("Used", f"{format_bytes(ram.used)} ({ram.percent} %)")
    print_row("Available", format_bytes(ram.available))
    swap = psutil.swap_memory()
    if swap.total:
        print_row("Swap", f"{format_bytes(swap.used)} / {format_bytes(swap.total)}")


def show_disks():
    print_title("Disks")
    if psutil:
        for part in psutil.disk_partitions():
            # Skip empty drives (e.g. CD-ROM on Windows)
            if "cdrom" in part.opts or not part.fstype:
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except PermissionError:
                continue
            print(f"{part.device} ({part.fstype})")
            print(f"  Total: {format_bytes(usage.total)} | "
                  f"Used: {format_bytes(usage.used)} ({usage.percent} %) | "
                  f"Free: {format_bytes(usage.free)}")
    else:
        # Fallback: only the main drive
        root = os.path.abspath(os.sep)
        usage = shutil.disk_usage(root)
        print(f"{root}")
        print(f"  Total: {format_bytes(usage.total)} | "
              f"Used: {format_bytes(usage.used)} | "
              f"Free: {format_bytes(usage.free)}")


def get_local_ip():
    """Find the local IP used for internet access (no data is actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return "N/A"
    finally:
        sock.close()


def show_network():
    print_title("Network")
    print_row("Local IP", get_local_ip())
    if psutil:
        for name, addrs in psutil.net_if_addrs().items():
            ipv4 = [a.address for a in addrs if a.family == socket.AF_INET]
            if ipv4:
                print_row(name[:18], ", ".join(ipv4))


def show_battery():
    if not psutil or not hasattr(psutil, "sensors_battery"):
        return
    battery = psutil.sensors_battery()
    if battery is None:  # desktop PC without battery
        return
    print_title("Battery")
    print_row("Level", f"{battery.percent:.0f} %")
    print_row("Charging", "Yes" if battery.power_plugged else "No")


def system_info():
    """Show a full system report (to be called from the menu)."""
    show_os()
    show_cpu()
    show_memory()
    show_disks()
    show_network()
    show_battery()

    if not psutil:
        print("\n[i] Install psutil for more details: pip install psutil")