import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "https://speed.cloudflare.com"
HEADERS = {"User-Agent": "Mozilla/5.0 (SpeedTest)"}


def to_mbps(num_bytes, seconds):
    """Convert bytes and seconds to megabits per second."""
    if seconds <= 0:
        return 0.0
    return (num_bytes * 8) / seconds / 1_000_000


def measure_ping(count=5):
    """Measure average latency and jitter using small requests (ms)."""
    times = []
    for _ in range(count):
        req = urllib.request.Request(f"{BASE_URL}/__down?bytes=0", headers=HEADERS)
        start = time.perf_counter()
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
        times.append((time.perf_counter() - start) * 1000)

    average = sum(times) / len(times)
    jitter = sum(abs(times[i] - times[i - 1]) for i in range(1, len(times))) / (len(times) - 1)
    return average, jitter


def download_chunk(size):
    """Download `size` bytes and return how many bytes were received."""
    req = urllib.request.Request(f"{BASE_URL}/__down?bytes={size}", headers=HEADERS)
    received = 0
    with urllib.request.urlopen(req, timeout=30) as resp:
        while True:
            data = resp.read(65536)
            if not data:
                break
            received += len(data)
    return received


def upload_chunk(size):
    """Upload `size` bytes of data and return the number of bytes sent."""
    payload = b"0" * size
    req = urllib.request.Request(
        f"{BASE_URL}/__up", data=payload, headers=HEADERS, method="POST"
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()
    return size


def measure_parallel(func, size, connections):
    """Run `func(size)` on several connections at once. Returns Mbps."""
    start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=connections) as pool:
        results = list(pool.map(func, [size] * connections))
    elapsed = time.perf_counter() - start
    return to_mbps(sum(results), elapsed)


def get_server_info():
    """Return (ip, city, country) of the test location, or None."""
    try:
        req = urllib.request.Request(f"{BASE_URL}/cdn-cgi/trace", headers=HEADERS)
        with urllib.request.urlopen(req, timeout=10) as resp:
            lines = resp.read().decode().splitlines()
        data = dict(line.split("=", 1) for line in lines if "=" in line)
        return data.get("ip", "N/A"), data.get("colo", "N/A"), data.get("loc", "N/A")
    except (urllib.error.URLError, OSError):
        return None


def speedtest():
    """Interactive internet speed test (to be called from the menu)."""
    print("\nStarting speed test (uses about 50-100 MB of data) ...")

    info = get_server_info()
    if info is None:
        print("[!] Could not reach the test server. Check your internet connection.")
        return
    ip, colo, loc = info
    print(f"Your IP     : {ip}")
    print(f"Server      : Cloudflare ({colo}), your country: {loc}")

    try:
        print("\nMeasuring latency ...")
        ping, jitter = measure_ping()
        print(f"Ping        : {ping:.0f} ms")
        print(f"Jitter      : {jitter:.0f} ms")

        print("\nTesting download ...")
        # Small warm-up run first, then the real measurement
        measure_parallel(download_chunk, 1_000_000, 2)
        download = measure_parallel(download_chunk, 10_000_000, 4)
        print(f"Download    : {download:.2f} Mbps")

        print("\nTesting upload ...")
        upload = measure_parallel(upload_chunk, 2_000_000, 4)
        print(f"Upload      : {upload:.2f} Mbps")

    except urllib.error.HTTPError as e:
        print(f"[!] Server returned an error: {e.code}")
        return
    except urllib.error.URLError as e:
        print(f"[!] Connection error: {e.reason}")
        return
    except (TimeoutError, OSError) as e:
        print(f"[!] Test failed: {e}")
        return
    except KeyboardInterrupt:
        print("\n[!] Test cancelled.")
        return

    print("\n--- Result ---")
    print(f"Ping {ping:.0f} ms | Download {download:.2f} Mbps | Upload {upload:.2f} Mbps")