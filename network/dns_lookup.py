import socket
import ipaddress


def is_ip(text):
    """Return True if the text is a valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def forward_lookup(domain):
    """Domain -> IP addresses. Returns (canonical_name, aliases, ipv4_list, ipv6_list)."""
    ipv4, ipv6 = [], []
    canonical = domain

    # getaddrinfo returns both IPv4 and IPv6 results
    for family, _, _, canon, sockaddr in socket.getaddrinfo(
        domain, None, proto=socket.IPPROTO_TCP, flags=socket.AI_CANONNAME
    ):
        if canon:
            canonical = canon
        ip = sockaddr[0]
        if family == socket.AF_INET and ip not in ipv4:
            ipv4.append(ip)
        elif family == socket.AF_INET6 and ip not in ipv6:
            ipv6.append(ip)

    return canonical, ipv4, ipv6


def reverse_lookup(ip):
    """IP -> hostname (PTR record). Returns (hostname, aliases)."""
    hostname, aliases, _ = socket.gethostbyaddr(ip)
    return hostname, aliases


def dns_lookup():
    """Interactive DNS lookup (to be called from the menu)."""
    query = input("Enter Domain or IP (e.g. example.com / 8.8.8.8): ").strip()
    if not query:
        print("[!] Nothing entered.")
        return

    # Reverse lookup: IP -> name
    if is_ip(query):
        print(f"\nReverse lookup for {query} ...")
        try:
            hostname, aliases = reverse_lookup(query)
        except socket.herror:
            print("[!] No PTR record found for this IP.")
            return
        except socket.gaierror:
            print("[!] Lookup failed.")
            return

        print(f"\nHostname : {hostname}")
        if aliases:
            print(f"Aliases  : {', '.join(aliases)}")
        return

    # Forward lookup: name -> IP
    print(f"\nLooking up {query} ...")
    try:
        canonical, ipv4, ipv6 = forward_lookup(query)
    except socket.gaierror:
        print(f"[!] Could not resolve '{query}' (domain not found or no internet).")
        return

    print(f"\nCanonical name : {canonical}")
    print(f"\nA records (IPv4) [{len(ipv4)}]:")
    for ip in ipv4:
        print(f"  {ip}")
    if not ipv4:
        print("  none")

    print(f"\nAAAA records (IPv6) [{len(ipv6)}]:")
    for ip in ipv6:
        print(f"  {ip}")
    if not ipv6:
        print("  none")