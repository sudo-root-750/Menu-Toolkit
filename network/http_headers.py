import http.client
import ssl
import time
from urllib.parse import urlparse

# Security headers worth checking (name -> what it protects against)
SECURITY_HEADERS = {
    "Strict-Transport-Security": "Forces HTTPS",
    "Content-Security-Policy": "Blocks XSS / injection",
    "X-Frame-Options": "Blocks clickjacking",
    "X-Content-Type-Options": "Blocks MIME sniffing",
    "Referrer-Policy": "Controls referrer info",
    "Permissions-Policy": "Controls browser features",
}


def parse_url(raw):
    """Turn 'example.com' or 'https://example.com/path' into (scheme, host, port, path)."""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ValueError("Invalid URL")
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError("Only http and https are supported")
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return scheme, parsed.hostname, port, path


def fetch_headers(scheme, host, port, path, timeout=10):
    """Send a HEAD request (falls back to GET). Returns (response, elapsed_seconds)."""
    if scheme == "https":
        conn = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ssl.create_default_context()
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    headers = {"User-Agent": "Mozilla/5.0 (HeaderChecker)", "Accept": "*/*"}
    try:
        start = time.time()
        conn.request("HEAD", path, headers=headers)
        response = conn.getresponse()

        # Some servers reject HEAD; retry with GET
        if response.status in (405, 501):
            conn.close()
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()

        elapsed = time.time() - start
        response.read(0)
        return response, elapsed, conn
    except Exception:
        conn.close()
        raise


def check_url(raw, max_redirects=5):
    """Follow redirects and return a list of (url, status, reason, headers, elapsed)."""
    scheme, host, port, path = parse_url(raw)
    chain = []

    for _ in range(max_redirects + 1):
        response, elapsed, conn = fetch_headers(scheme, host, port, path)
        url = f"{scheme}://{host}{path}"
        chain.append((url, response.status, response.reason, response.getheaders(), elapsed))

        location = response.getheader("Location")
        conn.close()

        if response.status in (301, 302, 303, 307, 308) and location:
            # Location can be relative (/login) or absolute (https://...)
            if location.startswith("/"):
                location = f"{scheme}://{host}{location}"
            scheme, host, port, path = parse_url(location)
        else:
            break

    return chain


def print_report(chain):
    """Print redirect chain, headers and security header summary."""
    if len(chain) > 1:
        print("\nRedirect chain:")
        for url, status, reason, _, _ in chain[:-1]:
            print(f"  {status} {url}")

    url, status, reason, headers, elapsed = chain[-1]
    print(f"\nFinal URL    : {url}")
    print(f"Status       : {status} {reason}")
    print(f"Response time: {elapsed * 1000:.0f} ms")

    print("\nResponse headers:")
    for name, value in headers:
        print(f"  {name}: {value[:100]}")

    present = {name.lower() for name, _ in headers}
    print("\nSecurity headers:")
    for name, purpose in SECURITY_HEADERS.items():
        mark = "[+]" if name.lower() in present else "[-]"
        print(f"  {mark} {name:<28} {purpose}")


def http_headers():
    """Interactive HTTP header checker (to be called from the menu)."""
    raw = input("Enter URL or Domain (e.g. example.com): ").strip()
    if not raw:
        print("[!] Nothing entered.")
        return

    print(f"\nChecking {raw} ...")
    try:
        chain = check_url(raw)
    except ValueError as e:
        print(f"[!] {e}")
        return
    except ssl.SSLCertVerificationError as e:
        print(f"[!] SSL certificate error: {e.verify_message}")
        return
    except TimeoutError:
        print("[!] Connection timed out.")
        return
    except OSError as e:
        print(f"[!] Connection error: {e}")
        return

    print_report(chain)