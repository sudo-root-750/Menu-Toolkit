"""Website Status Monitor: check several websites repeatedly and show up/down status."""
import http.client
import os
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from network.common import (IS_WINDOWS, USER_AGENT, ask, ask_int, clean_host,
                            format_duration)

DEFAULT_SITES = "https://example.com, https://www.wikipedia.org"


def normalize_url(raw):
    """'example.com' -> 'https://example.com/'. Returns '' for invalid input."""
    raw = raw.strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not clean_host(parsed.hostname or ""):
        return ""
    return raw


def check_site(url, timeout=8):
    """Return (status_code or None, milliseconds, problem text)."""
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
    started = time.perf_counter()
    try:
        if parsed.scheme == "https":
            conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        try:
            conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
            response = conn.getresponse()
            response.read(1024)
            return response.status, (time.perf_counter() - started) * 1000, ""
        finally:
            conn.close()
    except ssl.SSLCertVerificationError as error:
        return None, 0.0, f"SSL: {error.verify_message}"
    except (TimeoutError, OSError) as error:
        text = "timeout" if isinstance(error, TimeoutError) or "timed out" in str(error) else str(error)
        return None, 0.0, text[:40]
    except http.client.HTTPException as error:
        return None, 0.0, type(error).__name__


def is_up(status):
    return status is not None and status < 400


class SiteState:
    """Remembers what happened to one site across checks."""

    def __init__(self, url):
        self.url = url
        self.checks = 0
        self.failures = 0
        self.last_status = None
        self.last_ms = 0.0
        self.problem = ""
        self.up = None
        self.since = time.time()

    def update(self, status, ms, problem):
        """Update the state; returns a message if the site changed from up to down or back."""
        self.checks += 1
        now_up = is_up(status)
        if not now_up:
            self.failures += 1
        message = ""
        if self.up is not None and now_up != self.up:
            message = f"{self.url} is now {'UP' if now_up else 'DOWN'}"
        if self.up is None or now_up != self.up:
            self.since = time.time()
        self.up, self.last_status, self.last_ms = now_up, status, ms
        self.problem = problem or ("" if now_up else f"HTTP {status}")
        return message

    @property
    def availability(self):
        return (self.checks - self.failures) / self.checks * 100 if self.checks else 0.0


def render(states, events, started):
    lines = [f"Website Monitor  -  {time.strftime('%H:%M:%S')}  -  running {format_duration(time.time() - started)}"
             "  (Ctrl+C to stop)", ""]
    lines.append(f"{'SITE':<36}{'STATE':<8}{'CODE':<7}{'TIME':<10}{'UPTIME':<9}NOTE")
    lines.append("-" * 88)
    for s in states:
        state = "UP" if s.up else "DOWN"
        code = str(s.last_status) if s.last_status else "-"
        timing = f"{s.last_ms:.0f} ms" if s.up else "-"
        lines.append(f"{s.url[:34]:<36}{state:<8}{code:<7}{timing:<10}{s.availability:>5.1f}%   {s.problem}")
    if events:
        lines.append("")
        lines.append("Changes:")
        lines.extend(f"  {e}" for e in events[-6:])
    return lines


def clear_screen():
    if IS_WINDOWS:
        os.system("cls")
    else:
        print("\033[2J\033[H", end="")


def monitor(urls, interval, max_rounds=None, draw=True):
    states = [SiteState(u) for u in urls]
    events = []
    started = time.time()
    rounds = 0
    with ThreadPoolExecutor(max_workers=len(urls)) as pool:
        try:
            while max_rounds is None or rounds < max_rounds:
                begin = time.time()
                for state, result in zip(states, pool.map(check_site, urls)):
                    message = state.update(*result)
                    if message:
                        events.append(f"{time.strftime('%H:%M:%S')}  {message}")
                        print("\a", end="")
                rounds += 1
                if draw:
                    clear_screen()
                    print("\n".join(render(states, events, started)))
                if max_rounds is None or rounds < max_rounds:
                    time.sleep(max(0, interval - (time.time() - begin)))
        except KeyboardInterrupt:
            print("\n[!] Stopped.")
    return states


def site_monitor():
    """Interactive website monitor (to be called from the menu)."""
    raw = ask(f"Websites, comma separated [Enter = {DEFAULT_SITES}]: ", DEFAULT_SITES)
    urls = []
    for item in raw.split(","):
        url = normalize_url(item)
        if url and url not in urls:
            urls.append(url)
    if not urls:
        print("[!] No valid website.")
        return
    if len(urls) > 15:
        print("[!] Maximum 15 websites.")
        return
    interval = ask_int("Seconds between checks (5-3600)", 30, 5, 3600)
    if interval is None:
        return
    monitor(urls, interval)
