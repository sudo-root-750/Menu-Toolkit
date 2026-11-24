"""DNS Full Records: A, AAAA, CNAME, NS, MX, TXT, SOA and CAA records of a domain."""
import textwrap
from concurrent.futures import ThreadPoolExecutor

from network.common import ask, clean_host, is_ip
from network.dns_client import DNSError, get_system_dns, resolve, reverse_name

RECORD_TYPES = ["A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"]


def lookup_all(domain, server=None):
    """
    Query every record type in parallel.
    Returns {type: (rcode, records) or DNSError}.
    """
    def one(rtype):
        try:
            rcode, records, _ = resolve(domain, rtype, server)
            return rtype, (rcode, records)
        except DNSError as error:
            return rtype, error

    with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as pool:
        return dict(pool.map(one, RECORD_TYPES))


def sort_records(rtype, records):
    if rtype == "MX":
        return sorted(records, key=lambda r: int(r["data"].split()[0]))
    return sorted(records, key=lambda r: r["data"])


def print_records(rtype, records):
    print(f"\n{rtype} records ({len(records)}):")
    for record in sort_records(rtype, records):
        text = record["data"]
        if rtype == "TXT" and len(text) > 90:
            wrapped = textwrap.wrap(text, 90, break_long_words=True)
            print(f"  {wrapped[0]}")
            for part in wrapped[1:]:
                print(f"    {part}")
            print(f"    (TTL {record['ttl']}s)")
        else:
            print(f"  {text:<50} (TTL {record['ttl']}s)")


def reverse_lookup(ip, server):
    try:
        rcode, records, used = resolve(reverse_name(ip), "PTR", server)
    except DNSError as error:
        print(f"[!] DNS error: {error}")
        return
    print(f"\nPTR records for {ip} (server {used}):")
    if not records:
        print("  none (no reverse DNS name is set for this IP)")
    for record in records:
        print(f"  {record['data']}")


def dns_full():
    """Interactive full DNS lookup (to be called from the menu)."""
    raw = ask("Enter Domain or IP (e.g. example.com / 8.8.8.8): ")
    server_text = ask("DNS server [Enter = system default]: ")
    server = None
    if server_text:
        if not is_ip(server_text):
            print("[!] The DNS server must be an IP address (e.g. 1.1.1.1).")
            return
        server = server_text

    if is_ip(raw):
        reverse_lookup(raw, server)
        return

    domain = clean_host(raw)
    if not domain:
        print("[!] Invalid domain.")
        return

    print(f"\nLooking up {domain} using {server or ', '.join(get_system_dns())} ...")
    results = lookup_all(domain, server)

    if all(isinstance(r, DNSError) for r in results.values()):
        print(f"[!] No answer from the DNS server: {next(iter(results.values()))}")
        return
    if any(not isinstance(r, DNSError) and r[0] == "NXDOMAIN" for r in results.values()):
        print(f"[!] The domain '{domain}' does not exist (NXDOMAIN).")
        return

    shown = 0
    for rtype in RECORD_TYPES:
        result = results[rtype]
        if isinstance(result, DNSError):
            print(f"\n{rtype}: [!] {result}")
        elif result[0] not in ("NOERROR",):
            print(f"\n{rtype}: [!] server answered {result[0]}")
        elif result[1]:
            print_records(rtype, result[1])
            shown += 1
    if not shown:
        print("\nNo records found.")
