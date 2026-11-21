"""Simple HTTP Server: share a folder with other devices on your local network."""
import functools
import http.server
import os
import socket
import threading
import time

from network.common import ask, ask_int, ask_yes, clean_path, get_local_ip


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Serves files read-only and prints one short line per request."""

    def log_message(self, format, *args):
        print(f"  {time.strftime('%H:%M:%S')}  {self.client_address[0]:<15} {format % args}")

    def do_POST(self):
        self.send_error(405, "Read-only server")

    do_PUT = do_DELETE = do_POST


def make_server(folder, port, bind="0.0.0.0"):
    handler = functools.partial(QuietHandler, directory=folder)
    server = http.server.ThreadingHTTPServer((bind, port), handler)
    server.daemon_threads = True
    return server


def http_server():
    """Interactive file sharing server (to be called from the menu)."""
    folder = clean_path(ask("Folder to share [Enter = current folder]: ")) or os.getcwd()
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        print("[!] Folder not found.")
        return
    port = ask_int("Port (1024-65535)", 8000, 1024, 65535)
    if port is None:
        return

    everyone = ask_yes("Allow other devices on your network? (No = only this computer)", True)
    if everyone:
        print(f"\n[!] Everything inside this folder (and its subfolders) will be readable by anyone "
              f"on your network:\n    {folder}")
        if not ask_yes("Continue?"):
            return

    try:
        server = make_server(folder, port, "0.0.0.0" if everyone else "127.0.0.1")
    except OSError as error:
        print(f"[!] Could not start the server on port {port}: {error.strerror or error}")
        return

    local_ip = get_local_ip()
    print(f"\n[+] Sharing {folder}")
    print(f"    This computer : http://127.0.0.1:{port}")
    if everyone and local_ip:
        print(f"    Other devices : http://{local_ip}:{port}")
    print("    (Windows Firewall may ask for permission the first time.)")
    print("\nRequests (Ctrl+C to stop):")

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[!] Stopping the server ...")
    finally:
        server.shutdown()
        server.server_close()
    print("[+] Server stopped.")
