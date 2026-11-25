"""Robots / Sitemap Viewer: read robots.txt and sitemap.xml of a website."""
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

from network.common import USER_AGENT, ask, clean_host

MAX_BYTES = 3_000_000


def base_url(raw):
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not clean_host(parsed.hostname or ""):
        return ""
    return f"{parsed.scheme}://{parsed.netloc}"


def fetch(url, timeout=10):
    """Return (status, text). Status is None when the site could not be reached."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(MAX_BYTES)
            if data[:2] == b"\x1f\x8b":  # some sitemaps are served gzipped
                import gzip
                data = gzip.decompress(data)[:MAX_BYTES * 3]
            return response.status, data.decode(response.headers.get_content_charset() or "utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, ""
    except (urllib.error.URLError, OSError, ValueError):
        return None, ""


def parse_robots(text):
    """Return (groups, sitemaps). groups: {user_agent: {'allow': [...], 'disallow': [...], 'delay': str}}."""
    groups, sitemaps = {}, []
    agents, in_rules = [], False
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if in_rules:
                agents, in_rules = [], False
            agents.append(value)
            groups.setdefault(value, {"allow": [], "disallow": [], "delay": ""})
        elif key in ("allow", "disallow", "crawl-delay") and agents:
            in_rules = True
            for agent in agents:
                if key == "crawl-delay":
                    groups[agent]["delay"] = value
                elif value:
                    groups[agent][key].append(value)
        elif key == "sitemap" and value:
            sitemaps.append(value)
    return groups, sitemaps


def parse_sitemap(text):
    """Return (kind, urls) where kind is 'index', 'urlset' or 'invalid'."""
    try:
        root = ET.fromstring(text.encode("utf-8", "replace"))
    except ET.ParseError:
        return "invalid", []
    kind = "index" if root.tag.lower().endswith("sitemapindex") else "urlset"
    urls = []
    for element in root.iter():
        if element.tag.lower().endswith("}loc") or element.tag.lower() == "loc":
            if element.text and element.text.strip():
                urls.append(element.text.strip())
    return kind, urls


def show_robots(site):
    url = urljoin(site + "/", "robots.txt")
    print(f"\n=== {url} ===")
    status, text = fetch(url)
    if status is None:
        print("[!] The site could not be reached.")
        return []
    if status != 200 or not text.strip():
        print(f"[i] No robots.txt (HTTP {status}). All paths are allowed for crawlers.")
        return []
    if "<html" in text[:300].lower():
        print("[i] The server returned a web page instead of a robots.txt file.")
        return []

    groups, sitemaps = parse_robots(text)
    for agent, rules in groups.items():
        print(f"\nUser-agent: {agent}")
        if rules["delay"]:
            print(f"  Crawl-delay: {rules['delay']}")
        for path in rules["disallow"][:25]:
            print(f"  [-] Disallow: {path}")
        if len(rules["disallow"]) > 25:
            print(f"  ... {len(rules['disallow']) - 25} more disallow rules")
        for path in rules["allow"][:10]:
            print(f"  [+] Allow:    {path}")
    if sitemaps:
        print("\nSitemaps declared:")
        for s in sitemaps:
            print(f"  {s}")
    print("\n[i] robots.txt only asks crawlers to stay away. It is not a security measure, "
          "and listed paths are public information.")
    return sitemaps


def show_sitemap(url, depth=0, seen=None):
    seen = seen if seen is not None else set()
    if url in seen or len(seen) >= 8:
        return
    seen.add(url)
    status, text = fetch(url)
    indent = "  " * depth
    if status != 200 or not text:
        print(f"{indent}[!] {url}  (HTTP {status})")
        return
    kind, urls = parse_sitemap(text)
    if kind == "invalid":
        print(f"{indent}[!] {url}  is not valid XML")
    elif kind == "index":
        print(f"{indent}{url}  (index with {len(urls)} sitemaps)")
        for child in urls[:5]:
            show_sitemap(child, depth + 1, seen)
        if len(urls) > 5:
            print(f"{indent}  ... {len(urls) - 5} more sitemaps")
    else:
        print(f"{indent}{url}  ({len(urls)} URLs)")
        for page in urls[:8]:
            print(f"{indent}  {page}")
        if len(urls) > 8:
            print(f"{indent}  ... {len(urls) - 8} more URLs")


def robots_sitemap():
    """Interactive robots/sitemap viewer (to be called from the menu)."""
    site = base_url(ask("Enter website (e.g. example.com): "))
    if not site:
        print("[!] Invalid website.")
        return
    sitemaps = show_robots(site)
    print("\n=== Sitemap ===")
    targets = sitemaps[:3] or [urljoin(site + "/", "sitemap.xml")]
    for target in targets:
        show_sitemap(target)
