import socket

try:
    import psutil
except ImportError:
    psutil = None

# Connection states worth filtering on
STATES = {
    "1": ("ESTABLISHED", "Active connections"),
    "2": ("LISTEN", "Ports waiting for connections"),
    "3": ("TIME_WAIT", "Recently closed connections"),
}


def collect_connections():
    """Return a list of dicts describing every TCP/UDP connection."""
    # Map PID -> process name once (faster than asking per connection)
    names = {}
    for proc in psutil.process_iter(["pid", "name"]):
        names[proc.info["pid"]] = proc.info["name"] or "?"

    connections = []
    try:
        raw = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        return None  # macOS / some systems need administrator rights

    for c in raw:
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
        remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"
        connections.append({
            "proto": proto,
            "local": local,
            "remote": remote,
            "state": c.status if proto == "TCP" else "-",
            "pid": c.pid or 0,
            "process": names.get(c.pid, "-") if c.pid else "-",
        })
    return connections


def print_table(connections, limit=40):
    if not connections:
        print("\nNo connections found.")
        return

    print(f"\n{'PROTO':<7}{'LOCAL ADDRESS':<26}{'REMOTE ADDRESS':<26}{'STATE':<13}{'PID':<8}PROCESS")
    print("-" * 95)
    for c in connections[:limit]:
        print(f"{c['proto']:<7}{c['local'][:24]:<26}{c['remote'][:24]:<26}"
              f"{c['state']:<13}{c['pid']:<8}{c['process']}")

    if len(connections) > limit:
        print(f"... and {len(connections) - limit} more")
    print(f"\nTotal: {len(connections)}")


def show_by_state(state):
    connections = collect_connections()
    if connections is None:
        print("[!] Access denied. Run the program as administrator (or with sudo).")
        return
    selected = [c for c in connections if c["state"] == state]
    selected.sort(key=lambda c: c["local"])
    print_table(selected)


def show_udp():
    connections = collect_connections()
    if connections is None:
        print("[!] Access denied. Run the program as administrator (or with sudo).")
        return
    print_table([c for c in connections if c["proto"] == "UDP"])


def show_summary():
    """Count connections per process (who talks to the network the most)."""
    connections = collect_connections()
    if connections is None:
        print("[!] Access denied. Run the program as administrator (or with sudo).")
        return

    counts = {}
    for c in connections:
        if c["state"] == "ESTABLISHED":
            counts[c["process"]] = counts.get(c["process"], 0) + 1

    if not counts:
        print("\nNo established connections.")
        return

    print(f"\n{'PROCESS':<30}ESTABLISHED")
    print("-" * 42)
    for name, n in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"{name[:28]:<30}{n}")


def search_connections():
    """Find connections by process name, port or remote IP."""
    query = input("Enter process name, port or IP: ").strip().lower()
    if not query:
        print("[!] Nothing entered.")
        return

    connections = collect_connections()
    if connections is None:
        print("[!] Access denied. Run the program as administrator (or with sudo).")
        return

    found = [
        c for c in connections
        if query in c["process"].lower() or query in c["local"] or query in c["remote"]
    ]
    print_table(found, limit=60)


def open_connections():
    """Open connections menu (to be called from the System menu)."""
    if psutil is None:
        print("[!] psutil is not installed. Run: pip install psutil")
        return

    while True:
        choice = input(
            "\nOpen Connections: \n > 1.established \n > 2.listening ports"
            " \n > 3.udp \n > 4.per process summary \n > 5.search"
            " \n > 0.back \n>>>"
        ).strip()

        match choice:
            case "1":
                show_by_state("ESTABLISHED")
            case "2":
                show_by_state("LISTEN")
            case "3":
                show_udp()
            case "4":
                show_summary()
            case "5":
                search_connections()
            case "0":
                return
            case _:
                print("Invalid command. Try '1' to '5' or '0'.")