"""Shared helpers used by the network tools (input, formatting, menus, HTTP)."""
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import urllib.request

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"
USER_AGENT = "Mozilla/5.0 (TerminalToolkit)"

# Hostname: labels of letters/digits/-/_ (underscore allowed for names like _dmarc)
HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*$"
)

# Public "what is my IP" services (plain HTTPS, no API key)
PUBLIC_IP_SOURCES = [
    ("ipify", "https://api.ipify.org"),
    ("icanhazip", "https://icanhazip.com"),
    ("ifconfig.me", "https://ifconfig.me/ip"),
    ("Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"),
]


# ---------- Input ----------

def ask(prompt, default=""):
    """Read one line. Returns `default` when the user just presses Enter."""
    value = input(prompt).strip()
    return value or default


def ask_int(prompt, default, minimum, maximum):
    """Ask for a whole number. Returns None (after printing why) if invalid."""
    raw = input(f"{prompt} [Enter = {default}]: ").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print("[!] Please enter a number.")
        return None
    if not minimum <= value <= maximum:
        print(f"[!] Value must be between {minimum} and {maximum}.")
        return None
    return value


def ask_yes(prompt, default=False):
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({hint}): ").strip().lower()
    return default if not raw else raw in ("y", "yes")


def clean_path(raw):
    return raw.strip().strip('"').strip("'")


# ---------- Hosts and addresses ----------

def is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def is_valid_host(host):
    return bool(host) and (is_ip(host) or bool(HOST_RE.match(host)))


def clean_host(raw):
    """
    Turn 'example.com', 'https://example.com/path', 'user@example.com:8080'
    or '[::1]:80' into a bare, validated host. Returns '' if it is invalid.
    A host never starts with '-', so it is safe to pass to ping/traceroute.
    """
    raw = raw.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = re.split(r"[/?#]", raw, maxsplit=1)[0]
    if "@" in raw:
        raw = raw.rsplit("@", 1)[1]
    if raw.startswith("["):
        host = raw[1:].split("]", 1)[0]
    elif raw.count(":") == 1:
        host = raw.split(":", 1)[0]
    else:
        host = raw
    host = host.strip().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""
    if not is_valid_host(host):
        return ""
    # A name whose last part is only digits (e.g. "99" or "1.2.3") is not a real host name;
    # the operating system would silently read it as an odd IPv4 address like 0.0.0.99.
    if not is_ip(host) and host.rsplit(".", 1)[-1].isdigit():
        return ""
    return host


def get_local_ip():
    """Local IPv4 used for internet access (no packet is actually sent)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


# ---------- Formatting ----------

def format_bytes(size):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.1f} PB"


def format_rate(bytes_per_second):
    return format_bytes(bytes_per_second) + "/s"


def format_duration(seconds):
    seconds = int(seconds)
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")


def can_unicode():
    encoding = (getattr(sys.stdout, "encoding", None) or "").lower()
    return "utf" in encoding


def sparkline(values, low=None, high=None):
    """Tiny text graph. None values (lost packets) are drawn as 'x'."""
    bars = "▁▂▃▄▅▆▇█" if can_unicode() else "_.-~=*#@"
    numbers = [v for v in values if v is not None]
    if not numbers:
        return "x" * len(values)
    low = min(numbers) if low is None else low
    high = max(numbers) if high is None else high
    span = (high - low) or 1
    out = []
    for v in values:
        if v is None:
            out.append("x")
        else:
            out.append(bars[min(len(bars) - 1, int((v - low) / span * (len(bars) - 1)))])
    return "".join(out)


def stats(values):
    """Return (min, avg, max, jitter) for a list of numbers, or None if empty."""
    if not values:
        return None
    jitter = (sum(abs(values[i] - values[i - 1]) for i in range(1, len(values)))
              / (len(values) - 1)) if len(values) > 1 else 0.0
    return min(values), sum(values) / len(values), max(values), jitter


# ---------- Running programs and HTTP ----------

def run_cmd(cmd, timeout=15):
    """Run a program (no shell). Returns its output text, or None on failure."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace", timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (result.stdout or "") + (result.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return None


def http_get(url, timeout=10, max_bytes=2_000_000, headers=None):
    """Download a small text resource over http(s). Raises OSError on problems."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(max_bytes)
        charset = response.headers.get_content_charset() or "utf-8"
    return data.decode(charset, errors="replace")


def fetch_public_ip(timeout=6):
    """Return our public IP as a string, or '' if no service answered."""
    for _, url in PUBLIC_IP_SOURCES:
        try:
            text = http_get(url, timeout=timeout, max_bytes=2000).strip()
            if "ip=" in text:  # Cloudflare trace format
                text = dict(l.split("=", 1) for l in text.splitlines() if "=" in l).get("ip", "")
            if is_ip(text):
                return text
        except OSError:
            continue
    return ""


# ---------- Menu runner ----------

def run_menu(title, options):
    """
    Run a numbered menu until the user goes back.
    options: {"1": ("label", function), ...}. '0' = back, '00' = exit program.
    A crash or Ctrl+C inside a tool returns to the menu instead of closing the app.
    """
    while True:
        print(f"\n{title}")
        for key, (label, _) in options.items():
            print(f" > {key}.{label}")
        print(" > 0.back\n > 00.exit")

        choice = input(">>>").strip().lower()
        if choice == "0":
            return
        if choice == "00":
            print("bye")
            raise SystemExit
        if choice not in options:
            print(f"Invalid command. Try {', '.join(options)}, 0 or 00.")
            continue

        try:
            options[choice][1]()
        except KeyboardInterrupt:
            print("\n[!] Cancelled.")
        except SystemExit:
            raise
        except Exception as error:  # keep the app alive if one tool fails
            print(f"[!] The tool stopped because of an error: {type(error).__name__}: {error}")
