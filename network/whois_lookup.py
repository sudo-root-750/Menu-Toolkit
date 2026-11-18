import socket

# Starting point: IANA knows which server is responsible for each domain/IP
IANA_SERVER = "whois.iana.org"
WHOIS_PORT = 43


def query_server(server, query, timeout=10):
    """Send a query to a WHOIS server and return the raw text response."""
    with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode(errors="ignore")


def find_referral(text):
    """Find the next WHOIS server mentioned in a response (refer / whois line)."""
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key.strip().lower() in ("refer", "whois", "registrar whois server"):
            server = value.strip()
            if server:
                return server.replace("whois://", "").strip("/")
    return None


def whois_lookup(query):
    """Follow referrals: IANA -> registry -> registrar. Returns (server, text)."""
    server = IANA_SERVER
    text = query_server(server, query)

    # Follow up to 3 referrals to reach the most detailed server
    for _ in range(3):
        next_server = find_referral(text)
        if not next_server or next_server == server:
            break
        try:
            text = query_server(next_server, query)
            server = next_server
        except OSError:
            break  # keep the last good response
    return server, text


def clean_output(text):
    """Remove comment lines (%, #), empty lines and legal notices."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("%", "#", ">>>")):
            continue
        lines.append(line)
    return lines


def whois():
    """Interactive WHOIS lookup (to be called from the menu)."""
    query = input("Enter Domain or IP: ").strip()
    if not query:
        print("[!] Nothing entered.")
        return

    print(f"\nLooking up {query} ...")
    try:
        server, text = whois_lookup(query)
    except socket.gaierror:
        print("[!] Could not resolve the WHOIS server (check your internet).")
        return
    except socket.timeout:
        print("[!] Connection timed out.")
        return
    except OSError as e:
        print(f"[!] Connection error: {e}")
        return

    lines = clean_output(text)
    if not lines:
        print("[!] No data returned.")
        return

    print(f"Source: {server}\n")
    for line in lines:
        print(line)