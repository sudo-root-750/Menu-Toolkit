"""Email Records Checker: MX, SPF, DKIM and DMARC settings of a domain."""
from concurrent.futures import ThreadPoolExecutor

from network.common import ask, clean_host
from network.dns_client import DNSError, resolve

MARKS = {"ok": "[+]", "warn": "[!]", "fail": "[-]", "info": "[i]"}
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail",
                  "dkim", "s1", "s2", "mandrill", "smtp", "mxvault", "zoho"]
SPF_LOOKUP_MECHANISMS = ("include", "a", "mx", "ptr", "exists", "redirect")


def get_txt(name):
    """List of TXT strings, or None if the DNS query failed."""
    try:
        _, records, _ = resolve(name, "TXT")
    except DNSError:
        return None
    return [r["data"] for r in records]


def get_mx(domain):
    try:
        _, records, _ = resolve(domain, "MX")
    except DNSError:
        return None
    return sorted(records, key=lambda r: int(r["data"].split()[0]))


def mechanism_name(term):
    return term.lstrip("+-~?").split(":")[0].split("=")[0].split("/")[0].lower()


def count_spf_lookups(record, fetch, depth=0, budget=None):
    """Approximate number of DNS lookups an SPF record causes (the limit is 10)."""
    budget = budget if budget is not None else [20]  # safety cap on our own queries
    total = 0
    for term in record.split()[1:]:
        name = mechanism_name(term)
        if name not in SPF_LOOKUP_MECHANISMS:
            continue
        total += 1
        if name in ("include", "redirect") and depth < 5 and budget[0] > 0:
            target = term.split(":", 1)[1] if ":" in term else term.split("=", 1)[1] if "=" in term else ""
            if target:
                budget[0] -= 1
                texts = fetch(target) or []
                nested = next((t for t in texts if t.lower().startswith("v=spf1")), None)
                if nested:
                    total += count_spf_lookups(nested, fetch, depth + 1, budget)
    return total


def analyze_spf(texts, fetch=get_txt):
    """Return a list of (status, message)."""
    spf = [t for t in texts if t.lower().startswith("v=spf1")]
    if not spf:
        return [("fail", "No SPF record. Anyone can forge mail from this domain more easily.")]

    findings = []
    if len(spf) > 1:
        findings.append(("fail", "More than one SPF record (only one is allowed; receivers will reject all)."))
    record = spf[0]
    findings.append(("info", record[:110] + ("..." if len(record) > 110 else "")))

    terms = record.split()[1:]
    qualifier = next((t for t in terms if t.lstrip("+-~?") == "all"), None)
    if qualifier is None and not any(mechanism_name(t) == "redirect" for t in terms):
        findings.append(("warn", "No 'all' rule at the end (add -all or ~all)."))
    elif qualifier == "-all":
        findings.append(("ok", "Ends with -all (strict: unlisted servers are rejected)."))
    elif qualifier == "~all":
        findings.append(("ok", "Ends with ~all (soft fail: unlisted servers are marked suspicious)."))
    elif qualifier == "?all":
        findings.append(("warn", "Ends with ?all (neutral: gives no protection)."))
    elif qualifier in ("+all", "all"):
        findings.append(("fail", "Ends with +all: ANY server is allowed to send as this domain."))

    lookups = count_spf_lookups(record, fetch)
    if lookups > 10:
        findings.append(("fail", f"About {lookups} DNS lookups (limit is 10): SPF may fail with PermError."))
    else:
        findings.append(("ok", f"About {lookups} DNS lookups (limit is 10)."))
    return findings


def parse_tags(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def analyze_dmarc(texts):
    records = [t for t in texts if t.lower().startswith("v=dmarc1")]
    if not records:
        return [("fail", "No DMARC record. Receivers get no instruction about forged mail.")]
    if len(records) > 1:
        return [("fail", "More than one DMARC record (it is ignored).")]

    tags = parse_tags(records[0])
    findings = [("info", records[0][:110] + ("..." if len(records[0]) > 110 else ""))]
    policy = tags.get("p", "").lower()
    if policy == "reject":
        findings.append(("ok", "Policy p=reject: forged mail is rejected."))
    elif policy == "quarantine":
        findings.append(("ok", "Policy p=quarantine: forged mail goes to spam."))
    elif policy == "none":
        findings.append(("warn", "Policy p=none: monitoring only, forged mail is still delivered."))
    else:
        findings.append(("fail", "Missing or invalid p= policy."))
    if tags.get("pct", "100") != "100":
        findings.append(("warn", f"Only pct={tags['pct']}% of mail is checked."))
    if "rua" in tags:
        findings.append(("ok", "Aggregate reports (rua) are enabled."))
    else:
        findings.append(("info", "No rua= address: you will not receive DMARC reports."))
    return findings


def find_dkim(domain):
    """Selectors (from a common list) that have a DKIM key."""
    def check(selector):
        texts = get_txt(f"{selector}._domainkey.{domain}") or []
        return selector if any("p=" in t and ("v=dkim1" in t.lower() or "k=" in t.lower()) for t in texts) else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        return [s for s in pool.map(check, DKIM_SELECTORS) if s]


def show(findings):
    for status, message in findings:
        print(f"  {MARKS[status]} {message}")


def email_records():
    """Interactive email records checker (to be called from the menu)."""
    domain = clean_host(ask("Enter Domain (e.g. example.com): "))
    if not domain or "." not in domain:
        print("[!] Invalid domain.")
        return

    print(f"\nChecking email settings of {domain} ...")

    print("\nMX (mail servers):")
    mx = get_mx(domain)
    if mx is None:
        print("  [!] DNS query failed.")
    elif not mx:
        print("  [!] No MX records: this domain cannot receive email.")
    else:
        for record in mx:
            print(f"  [+] {record['data']}")

    print("\nSPF (who may send mail):")
    texts = get_txt(domain)
    if texts is None:
        print("  [!] DNS query failed.")
    else:
        show(analyze_spf(texts))

    print("\nDMARC (what to do with forged mail):")
    texts = get_txt(f"_dmarc.{domain}")
    if texts is None:
        print("  [!] DNS query failed.")
    else:
        show(analyze_dmarc(texts))

    print("\nDKIM (mail signing keys):")
    selectors = find_dkim(domain)
    if selectors:
        print(f"  [+] Key found for selector(s): {', '.join(selectors)}")
    else:
        print("  [i] No key found for the common selector names. Your provider may use another "
              "selector name, so this is not necessarily a problem.")
