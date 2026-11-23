"""Domain Expiry Checker: read the expiry date from WHOIS and warn when it is close."""
import re
import time
from datetime import datetime, timezone

try:  # the WHOIS tool built earlier in this project
    from network.whois_lookup import whois_lookup
except ImportError:
    whois_lookup = None

from network.common import ask, clean_host

EXPIRY_KEYS = (
    r"registry expiry date|registrar registration expiration date|expiration date|"
    r"expiry date|expires on|expires|paid-till|expire-date|expire date|renewal date"
)
EXPIRY_RE = re.compile(rf"^\s*(?:{EXPIRY_KEYS})\s*[:\]]\s*(.+)$", re.I | re.M)
DATE_FORMATS = ("%Y-%m-%d", "%Y.%m.%d", "%Y/%m/%d", "%d-%b-%Y", "%d.%m.%Y", "%d/%m/%Y",
                "%Y-%m-%d %H:%M:%S", "%d-%b-%Y %H:%M:%S", "%Y%m%d")


def parse_date(text):
    """Parse the many date styles used by WHOIS servers. Returns a naive UTC datetime or None."""
    parts = text.strip().split()
    if not parts:
        return None
    for candidate in (text.strip(), parts[0], " ".join(parts[:2])):
        iso = candidate[:-1] + "+00:00" if candidate.endswith("Z") else candidate
        try:
            value = datetime.fromisoformat(iso)
            if value.tzinfo:
                value = value.astimezone(timezone.utc).replace(tzinfo=None)
            return value
        except ValueError:
            pass
        for fmt in DATE_FORMATS:
            try:
                return datetime.strptime(candidate, fmt)
            except ValueError:
                continue
    return None


def find_expiry(whois_text):
    """First parsable expiry date in a WHOIS answer, or None."""
    for match in EXPIRY_RE.finditer(whois_text):
        value = parse_date(match.group(1))
        if value:
            return value
    return None


def days_left(expiry, now=None):
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    return (expiry - now).days


def status_for(days):
    if days < 0:
        return "[-] EXPIRED"
    if days <= 30:
        return "[-] renew now"
    if days <= 60:
        return "[!] renew soon"
    return "[+] ok"


def domain_expiry():
    """Interactive expiry checker (to be called from the menu)."""
    if whois_lookup is None:
        print("[!] This tool needs network/whois_lookup.py (the WHOIS tool) in the same folder.")
        return

    raw = ask("Enter domain(s), comma separated (e.g. example.com, example.org): ")
    domains = []
    for item in raw.split(","):
        host = clean_host(item)
        if host and "." in host and host not in domains:
            domains.append(host)
    if not domains:
        print("[!] No valid domain.")
        return
    if len(domains) > 20:
        print("[!] Maximum 20 domains per check (WHOIS servers limit requests).")
        return

    rows = []
    for index, domain in enumerate(domains):
        print(f"Checking {domain} ...")
        try:
            _, text = whois_lookup(domain)
            expiry = find_expiry(text)
            rows.append((domain, expiry, None if expiry else "no expiry date in WHOIS answer"))
        except OSError as error:
            rows.append((domain, None, f"WHOIS error: {error}"))
        if index < len(domains) - 1:
            time.sleep(1)  # be polite to WHOIS servers

    rows.sort(key=lambda r: (r[1] is None, r[1] or datetime.max))
    print(f"\n{'DOMAIN':<32}{'EXPIRES':<14}{'DAYS LEFT':<11}STATUS")
    print("-" * 70)
    for domain, expiry, problem in rows:
        if expiry is None:
            print(f"{domain[:30]:<32}{'-':<14}{'-':<11}[i] {problem}")
        else:
            days = days_left(expiry)
            print(f"{domain[:30]:<32}{expiry:%Y-%m-%d}  {days:<11}{status_for(days)}")
    print("\n[i] Some registries (and privacy services) hide or change the date format.")
