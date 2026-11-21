"""Network Monitor: live download/upload speed of every network interface."""
import os
import time

from network.common import (IS_WINDOWS, ask_int, format_bytes, format_rate,
                            sparkline)

try:
    import psutil
except ImportError:
    psutil = None

HISTORY = 40


def rates(previous, current, seconds):
    """Bytes per second for each interface between two psutil snapshots."""
    result = {}
    for name, now in current.items():
        before = previous.get(name)
        if before is None or seconds <= 0:
            continue
        # Counters can reset (interface restarted): never show negative speeds
        down = max(0, now.bytes_recv - before.bytes_recv) / seconds
        up = max(0, now.bytes_sent - before.bytes_sent) / seconds
        result[name] = (down, up)
    return result


def clear_screen():
    if IS_WINDOWS:
        os.system("cls")
    else:
        print("\033[2J\033[H", end="")


def active_names(counters, stats):
    """Interfaces that are up and have carried some traffic."""
    return [n for n, c in counters.items()
            if n in stats and stats[n].isup and (c.bytes_recv or c.bytes_sent)]


def network_monitor():
    """Interactive live network monitor (to be called from the menu)."""
    if psutil is None:
        print("[!] psutil is not installed. Run: pip install psutil")
        return
    interval = ask_int("Seconds between updates (1-10)", 1, 1, 10)
    if interval is None:
        return

    history = {}
    start_counters = psutil.net_io_counters(pernic=True)
    previous, last_time = start_counters, time.time()
    peak_down = peak_up = 0.0
    try:
        while True:
            time.sleep(interval)
            now = time.time()
            current = psutil.net_io_counters(pernic=True)
            speeds = rates(previous, current, now - last_time)
            previous, last_time = current, now
            names = active_names(current, psutil.net_if_stats())

            clear_screen()
            print(f"Network Monitor  -  {time.strftime('%H:%M:%S')}  (Ctrl+C to stop)\n")
            print(f"{'INTERFACE':<22}{'DOWNLOAD':>14}{'UPLOAD':>14}{'TOTAL RX':>12}{'TOTAL TX':>12}  GRAPH (download)")
            print("-" * 100)
            total_down = total_up = 0.0
            for name in names:
                down, up = speeds.get(name, (0.0, 0.0))
                total_down += down
                total_up += up
                history.setdefault(name, []).append(down)
                history[name] = history[name][-HISTORY:]
                print(f"{name[:20]:<22}{format_rate(down):>14}{format_rate(up):>14}"
                      f"{format_bytes(current[name].bytes_recv):>12}{format_bytes(current[name].bytes_sent):>12}"
                      f"  {sparkline(history[name], low=0)}")
            peak_down, peak_up = max(peak_down, total_down), max(peak_up, total_up)
            print("-" * 100)
            print(f"{'ALL':<22}{format_rate(total_down):>14}{format_rate(total_up):>14}")
            print(f"\nPeak: download {format_rate(peak_down)} | upload {format_rate(peak_up)}")
            print("Speeds are in bytes per second (multiply by 8 for bits; 1 MB/s = 8 Mbps).")
    except KeyboardInterrupt:
        print("\n[!] Stopped.")

    end = psutil.net_io_counters(pernic=True)
    down = sum(max(0, end[n].bytes_recv - start_counters[n].bytes_recv) for n in end if n in start_counters)
    up = sum(max(0, end[n].bytes_sent - start_counters[n].bytes_sent) for n in end if n in start_counters)
    print(f"\nTransferred during this session: downloaded {format_bytes(down)}, uploaded {format_bytes(up)}")
