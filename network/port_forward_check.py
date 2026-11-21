"""Port Forward Checker: is one of YOUR ports reachable from the internet?"""
import ipaddress
import socket
import threading

from network.common import ask, ask_int, ask_yes, fetch_public_ip, get_local_ip


def parse_port(text):
    if not text.isdigit() or not 1 <= int(text) <= 65535:
        return None
    return int(text)


def can_connect(ip, port, timeout=4.0):
    """True when something accepts a TCP connection at ip:port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def start_test_listener(port):
    """Open a temporary listening socket so a closed port can be tested. Returns (socket, stop_event)."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", port))
    listener.listen(5)
    listener.settimeout(0.5)
    stop = threading.Event()

    def accept_loop():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                return

    threading.Thread(target=accept_loop, daemon=True).start()
    return listener, stop


def port_forward_check():
    """Interactive port forwarding check (to be called from the menu)."""
    print("[i] This tests YOUR OWN public IP. It connects from this computer to your public address,\n"
          "    which on many routers does not work (no 'NAT loopback'). A 'closed' result here\n"
          "    is therefore a hint, not proof; test from mobile data for a certain answer.\n")
    port = parse_port(ask("Port to test (1-65535): "))
    if port is None:
        print("[!] Invalid port.")
        return

    print("\nFinding your public IP ...")
    public = fetch_public_ip()
    if not public:
        print("[!] Could not find your public IP (offline, or services are blocked).")
        return
    ip = ipaddress.ip_address(public)
    if ip.version != 4:
        print(f"[i] Your public address is IPv6 ({public}). Port forwarding is an IPv4/NAT topic; "
              "for IPv6 check the router firewall instead.")
        return
    print(f"Public IP : {public}")
    print(f"Local IP  : {get_local_ip() or '?'}")

    listener = stop = None
    if not can_connect("127.0.0.1", port, timeout=1.0):
        print(f"\nNothing is listening on port {port} on this computer.")
        if ask_yes("Open a temporary test listener on this port for the check?", True):
            try:
                listener, stop = start_test_listener(port)
            except OSError as error:
                print(f"[!] Could not open port {port}: {error.strerror or error}")
                return
            print(f"Temporary listener started on port {port}.")

    try:
        print(f"\nConnecting to {public}:{port} ...")
        reachable = can_connect(public, port)
    finally:
        if stop:
            stop.set()
        if listener:
            listener.close()

    if reachable:
        print(f"\n[+] {public}:{port} accepts connections. The port looks reachable.")
        print("[!] Make sure that is intended: open ports are a common way in for attackers.")
    else:
        print(f"\n[-] {public}:{port} did not answer.")
        print("    Possible reasons: no port forward on the router, a firewall, your ISP blocks the port,\n"
              "    carrier-grade NAT (no real public IP), or the router does not support NAT loopback.")
