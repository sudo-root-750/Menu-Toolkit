"""IP Blacklist Check: look an IPv4 address up in public spam/abuse lists (DNSBL)."""
import ipaddress
from concurrent.futures import ThreadPoolExecutor

from network.common import ask, clean_host
from network.dns_client import DNSError, resolve

# (name, zone). A listing is an A record answer in 127.0.0.0/8.
# Some lists refuse queries sent through big public resolvers; those answers are reported as 'blocked'.
BLACKLISTS = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Barracuda", "b.barracudacentral.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("SORBS (spam)", "spam.dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
    ("PSBL", "psbl.surriel.com"),
    ("DroneBL", "dnsbl.dronebl.org"),
    ("Abuseat CBL", "cbl.abuseat.org"),
    ("Manitu NiX", "ix.dnsbl.manitu.net"),
    ("Truncate", "truncate.gbudb.net"),
]


def reverse_ipv4(ip):
    return ".".join(reversed(ip.split(".")))


def interpret(zone, answers):
    """Return ('listed' | 'clean' | 'blocked', detail)."""
    if not answers:
        return "clean", ""
    codes = [a["data"] for a in answers if a["type"] == "A"]
    if not codes:
        return "clean", ""
    # Spamhaus answers 127.255.255.x when it refuses to answer (open resolver / rate limit)
    if any(c.startswith("127.255.255.") for c in codes):
        return "blocked", "the list refused the query (use your own DNS server)"
    if not all(c.startswith("127.") for c in codes):
        return "blocked", "unexpected answer (resolver may rewrite DNS)"
    return "listed", ", ".join(codes)


def check_one(ip, zone, server=None):
    name = f"{reverse_ipv4(ip)}.{zone}"
    try:
        rcode, answers, _ = resolve(name, "A", server)
    except DNSError as error:
        return "error", str(error)
    if rcode == "NXDOMAIN":
        return "clean", ""
    if rcode != "NOERROR":
        return "error", rcode
    return interpret(zone, answers)


def check_all(ip, server=None, lists=BLACKLISTS):
    """Returns a list of (name, status, detail)."""
    def one(item):
        name, zone = item
        status, detail = check_one(ip, zone, server)
        return name, status, detail

    with ThreadPoolExecutor(max_workers=len(lists)) as pool:
        return list(pool.map(one, lists))


def ip_blacklist():
    """Interactive blacklist check (to be called from the menu)."""
    raw = ask("Enter IPv4 address or domain: ")
    try:
        ip = str(ipaddress.IPv4Address(raw))
    except ValueError:
        host = clean_host(raw)
        ips = []
        if host:
            try:
                _, records, _ = resolve(host, "A")
                ips = [r["data"] for r in records if r["type"] == "A"]
            except DNSError:
                pass
        if not ips:
            print("[!] Enter a valid IPv4 address, or a domain that resolves to one.")
            return
        ip = ips[0]
        print(f"{raw} -> {ip}")

    if not ipaddress.ip_address(ip).is_global:
        print("[!] Private and special addresses are never listed. Enter a public IP.")
        return

    print(f"\nChecking {ip} in {len(BLACKLISTS)} lists ...\n")
    results = check_all(ip)
    marks = {"clean": "[+]", "listed": "[-]", "blocked": "[i]", "error": "[i]"}
    for name, status, detail in results:
        print(f"{marks[status]} {name:<18}{status:<9}{detail}")

    listed = [r for r in results if r[1] == "listed"]
    unknown = [r for r in results if r[1] in ("blocked", "error")]
    print()
    if listed:
        print(f"[-] Listed on {len(listed)} list(s). Mail from this IP may be rejected or sent to spam.")
        print("    Visit each list's website to see the reason and the removal process.")
    else:
        print("[+] Not listed on the lists that answered.")
    if unknown:
        print(f"[i] {len(unknown)} list(s) gave no usable answer; their result is unknown.")
