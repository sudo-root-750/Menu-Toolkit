"""LAN Transfer: send a file or a chat message between two computers with sockets."""
import hashlib
import json
import os
import socket
import struct
import threading
import time

from network.common import (ask, ask_int, ask_yes, clean_host, clean_path,
                            format_bytes, get_local_ip)

DEFAULT_PORT = 5001
CHUNK = 64 * 1024
MAX_HEADER = 65536
MAX_MESSAGE = 65536


# ---------- Framing: 4-byte length + JSON header ----------

def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def send_header(sock, header):
    raw = json.dumps(header).encode("utf-8")
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def recv_header(sock):
    (size,) = struct.unpack(">I", recv_exact(sock, 4))
    if size > MAX_HEADER:
        raise ValueError("Header too large")
    return json.loads(recv_exact(sock, size).decode("utf-8"))


def safe_name(name):
    """Only keep the last part of a received file name (blocks '../../' tricks)."""
    name = os.path.basename(str(name).replace("\\", "/")).strip(" .")
    return "".join("_" if c in '<>:"|?*\x00' or ord(c) < 32 else c for c in name) or "received.bin"


def unique_path(path):
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    for number in range(1, 1000):
        if not os.path.exists(f"{base} ({number}){ext}"):
            return f"{base} ({number}){ext}"
    return path


# ---------- File transfer ----------

def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def send_file(host, port, path, progress=None):
    size = os.path.getsize(path)
    digest = file_sha256(path)
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(60)
        send_header(sock, {"type": "file", "name": os.path.basename(path), "size": size, "sha256": digest})
        answer = recv_header(sock)
        if not answer.get("accept"):
            return False, "The receiver declined the file."
        sent = 0
        with open(path, "rb") as handle:
            while chunk := handle.read(CHUNK):
                sock.sendall(chunk)
                sent += len(chunk)
                if progress:
                    progress(sent, size)
        result = recv_header(sock)
    return bool(result.get("ok")), result.get("message", "")


def receive_file(conn, header, folder, confirm=None, progress=None):
    """Handle a 'file' header on an accepted connection. Returns a status text."""
    name, size = safe_name(header.get("name", "")), int(header.get("size", 0))
    if size < 0:
        send_header(conn, {"accept": False})
        return "Invalid file size."
    if confirm and not confirm(name, size):
        send_header(conn, {"accept": False})
        return f"Declined: {name}"
    send_header(conn, {"accept": True})

    path = unique_path(os.path.join(folder, name))
    digest, received = hashlib.sha256(), 0
    with open(path, "wb") as handle:
        while received < size:
            chunk = conn.recv(min(CHUNK, size - received))
            if not chunk:
                break
            handle.write(chunk)
            digest.update(chunk)
            received += len(chunk)
            if progress:
                progress(received, size)
    ok = received == size and digest.hexdigest() == header.get("sha256")
    if not ok:
        try:
            os.remove(path)
        except OSError:
            pass
    try:
        send_header(conn, {"ok": ok, "message": "Received and verified." if ok else "File is damaged."})
    except OSError:
        pass
    return f"Saved {path} ({format_bytes(size)}), checksum OK" if ok else "Transfer failed or file damaged."


# ---------- Menu actions ----------

def progress_printer():
    state = {"last": 0.0}

    def show(done, total):
        now = time.time()
        if now - state["last"] > 0.25 or done == total:
            percent = done / total * 100 if total else 100
            print(f"\r  {percent:5.1f}%  {format_bytes(done)} / {format_bytes(total)}".ljust(60), end="", flush=True)
            state["last"] = now
    return show


def do_send_file():
    host = clean_host(ask("Receiver IP or name: "))
    if not host:
        print("[!] Invalid address.")
        return
    port = ask_int("Port", DEFAULT_PORT, 1, 65535)
    path = clean_path(ask("File to send: "))
    if port is None:
        return
    if not os.path.isfile(path):
        print("[!] File not found.")
        return
    print(f"\nSending {os.path.basename(path)} ({format_bytes(os.path.getsize(path))}) ...")
    try:
        ok, message = send_file(host, port, path, progress_printer())
    except (OSError, ValueError, ConnectionError) as error:
        print(f"\n[!] Could not send: {error}")
        return
    print(f"\n{'[+]' if ok else '[-]'} {message}")


def do_send_message():
    host = clean_host(ask("Receiver IP or name: "))
    if not host:
        print("[!] Invalid address.")
        return
    port = ask_int("Port", DEFAULT_PORT, 1, 65535)
    if port is None:
        return
    text = ask("Message: ")[:MAX_MESSAGE]
    if not text:
        print("[!] Nothing entered.")
        return
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            send_header(sock, {"type": "message", "text": text, "from": socket.gethostname()})
            recv_header(sock)
        print("[+] Message delivered.")
    except (OSError, ValueError, ConnectionError) as error:
        print(f"[!] Could not send: {error}")


def do_receive():
    port = ask_int("Listen on port", DEFAULT_PORT, 1024, 65535)
    if port is None:
        return
    folder = os.path.abspath(clean_path(ask("Save received files to [Enter = current folder]: ")) or os.getcwd())
    if not os.path.isdir(folder):
        print("[!] Folder not found.")
        return
    auto_accept = ask_yes("Accept files automatically? (No = ask each time)")

    try:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(5)
        listener.settimeout(0.5)
    except OSError as error:
        print(f"[!] Could not listen on port {port}: {error.strerror or error}")
        return

    print(f"\n[+] Waiting on {get_local_ip() or '0.0.0.0'}:{port}  ->  saving to {folder}")
    print("    Tell the sender this address. Ctrl+C to stop.\n")
    try:
        while True:
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(60)
                try:
                    header = recv_header(conn)
                    if header.get("type") == "message":
                        print(f"\n[{time.strftime('%H:%M:%S')}] {str(header.get('from', addr[0]))[:40]} "
                              f"({addr[0]}): {str(header.get('text', ''))[:MAX_MESSAGE]}")
                        send_header(conn, {"ok": True})
                    elif header.get("type") == "file":
                        confirm = None if auto_accept else (
                            lambda n, s, a=addr[0]: ask_yes(f"\n{a} wants to send '{n}' ({format_bytes(s)}). Accept?"))
                        print(f"\n[{addr[0]}] receiving ...")
                        print("\n  " + receive_file(conn, header, folder, confirm, progress_printer()))
                except (OSError, ValueError, ConnectionError, struct.error, KeyError, TypeError) as error:
                    print(f"\n[!] Connection from {addr[0]} failed: {error}")
    except KeyboardInterrupt:
        print("\n[!] Stopped listening.")
    finally:
        listener.close()


def lan_transfer():
    """LAN transfer menu (to be called from the Network menu)."""
    while True:
        choice = input("\nLAN Transfer: \n > 1.receive (wait for files/messages) \n > 2.send file"
                       " \n > 3.send message \n > 0.back \n>>>").strip()
        if choice == "1":
            do_receive()
        elif choice == "2":
            do_send_file()
        elif choice == "3":
            do_send_message()
        elif choice == "0":
            return
        else:
            print("Invalid command. Try '1', '2', '3' or '0'.")
