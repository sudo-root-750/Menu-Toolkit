import time

try:
    import psutil
except ImportError:
    psutil = None


def format_bytes(size):
    """Convert bytes to a readable string (e.g. 8589934592 -> 8.00 GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def collect_processes():
    """Return a list of dicts with info about every running process."""
    # First call starts the CPU measurement for each process
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    time.sleep(1)  # CPU usage needs a time window to be measured

    processes = []
    cpu_count = psutil.cpu_count() or 1
    for proc in psutil.process_iter(["pid", "name", "username", "memory_info", "status"]):
        try:
            info = proc.info
            memory = info["memory_info"].rss if info["memory_info"] else 0
            processes.append({
                "pid": info["pid"],
                "name": info["name"] or "?",
                "user": (info["username"] or "?").split("\\")[-1],
                "status": info["status"],
                "memory": memory,
                # Divide by core count so the total stays within 100 %
                "cpu": proc.cpu_percent(None) / cpu_count,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes


def print_table(processes, limit):
    print(f"\n{'PID':<8}{'NAME':<28}{'USER':<16}{'CPU %':<8}{'MEMORY':<12}STATUS")
    print("-" * 80)
    for p in processes[:limit]:
        print(f"{p['pid']:<8}{p['name'][:26]:<28}{p['user'][:14]:<16}"
              f"{p['cpu']:<8.1f}{format_bytes(p['memory']):<12}{p['status']}")


def show_top(sort_by):
    """Show the top 15 processes sorted by 'memory' or 'cpu'."""
    print("\nReading processes ...")
    processes = collect_processes()
    processes.sort(key=lambda p: p[sort_by], reverse=True)
    print_table(processes, 15)
    print(f"\nTotal processes: {len(processes)}")


def search_process():
    """Find processes by (part of) their name."""
    query = input("Enter process name (e.g. chrome): ").strip().lower()
    if not query:
        print("[!] Nothing entered.")
        return

    print("\nReading processes ...")
    found = [p for p in collect_processes() if query in p["name"].lower()]
    if not found:
        print(f"[!] No process matches '{query}'.")
        return

    found.sort(key=lambda p: p["memory"], reverse=True)
    print_table(found, 50)
    total_mem = sum(p["memory"] for p in found)
    print(f"\nMatches: {len(found)} | Total memory: {format_bytes(total_mem)}")


def kill_process():
    """Terminate a process by PID (asks for confirmation first)."""
    try:
        pid = int(input("Enter PID to terminate: ").strip())
        proc = psutil.Process(pid)
        name = proc.name()
    except ValueError:
        print("[!] PID must be a number.")
        return
    except psutil.NoSuchProcess:
        print("[!] No process with this PID.")
        return
    except psutil.AccessDenied:
        print("[!] Access denied.")
        return

    answer = input(f"Terminate '{name}' (PID {pid})? (y/n): ").strip().lower()
    if answer != "y":
        print("Cancelled.")
        return

    try:
        proc.terminate()
        proc.wait(timeout=3)
        print(f"[+] {name} (PID {pid}) terminated.")
    except psutil.TimeoutExpired:
        print("[!] Process did not close. It may need administrator rights.")
    except psutil.AccessDenied:
        print("[!] Access denied. Run the program as administrator.")
    except psutil.NoSuchProcess:
        print("[+] Process already closed.")


def process_viewer():
    """Process viewer menu (to be called from the System menu)."""
    if psutil is None:
        print("[!] psutil is not installed. Run: pip install psutil")
        return

    while True:
        choice = input(
            "\nProcess Viewer: \n > 1.top by memory \n > 2.top by cpu"
            " \n > 3.search by name \n > 4.terminate process \n > 0.back \n>>>"
        ).strip()

        match choice:
            case "1":
                show_top("memory")
            case "2":
                show_top("cpu")
            case "3":
                search_process()
            case "4":
                kill_process()
            case "0":
                return
            case _:
                print("Invalid command. Try '1', '2', '3', '4' or '0'.")