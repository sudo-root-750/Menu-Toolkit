"""File Download Tool: download a file with a progress bar, speed and resume support."""
import os
import re
import time
import urllib.error
import urllib.request
from urllib.parse import unquote, urlparse

from network.common import (USER_AGENT, ask, ask_yes, clean_host,
                            format_bytes, format_duration)

CHUNK = 64 * 1024


def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not clean_host(parsed.hostname or ""):
        return ""
    return raw


def safe_filename(url, content_disposition=""):
    """Pick a file name that cannot escape the target folder."""
    name = ""
    match = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", content_disposition or "", re.I)
    if match:
        name = unquote(match.group(1))
    if not name:
        name = unquote(os.path.basename(urlparse(url).path))
    name = os.path.basename(name.replace("\\", "/"))
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name).strip(" .")
    return name or "download.bin"


def unique_path(path):
    """file.zip -> file (1).zip if file.zip already exists."""
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    for number in range(1, 1000):
        candidate = f"{base} ({number}){ext}"
        if not os.path.exists(candidate):
            return candidate
    return path


def progress_line(done, total, speed):
    if total:
        percent = done / total * 100
        filled = int(25 * done / total)
        remaining = (total - done) / speed if speed else 0
        eta = format_duration(remaining) if speed else "?"
        return (f"[{'#' * filled}{'-' * (25 - filled)}] {percent:5.1f}%  "
                f"{format_bytes(done)} / {format_bytes(total)}  {format_bytes(speed)}/s  ETA {eta}")
    return f"{format_bytes(done)} downloaded  {format_bytes(speed)}/s"


def download(url, folder, resume_ok=True, timeout=20):
    """
    Download `url` into `folder`. Returns (path, bytes_total).
    Continues an interrupted '.part' file when the server supports it.
    Raises OSError / urllib.error.URLError on failure.
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as head:  # first request: learn the name
        name = safe_filename(head.geturl(), head.headers.get("Content-Disposition", ""))
        total = int(head.headers.get("Content-Length") or 0)
        accepts_ranges = "bytes" in (head.headers.get("Accept-Ranges") or "").lower()
        final_url = head.geturl()

    final_path = os.path.join(folder, name)
    part_path = final_path + ".part"
    offset = os.path.getsize(part_path) if resume_ok and accepts_ranges and os.path.exists(part_path) else 0
    if total and offset >= total:
        offset = 0

    headers = {"User-Agent": USER_AGENT}
    if offset:
        headers["Range"] = f"bytes={offset}-"
        print(f"Resuming from {format_bytes(offset)} ...")
    request = urllib.request.Request(final_url, headers=headers)

    mode = "ab" if offset else "wb"
    started, done = time.time(), offset
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if offset and response.status != 206:  # server ignored the range request: start over
            offset, done, mode = 0, 0, "wb"
        with open(part_path, mode) as handle:
            last_print = 0.0
            while True:
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                handle.write(chunk)
                done += len(chunk)
                now = time.time()
                if now - last_print >= 0.3:
                    speed = (done - offset) / max(now - started, 0.001)
                    print("\r" + progress_line(done, total, speed).ljust(100), end="", flush=True)
                    last_print = now
    if total and done < total:
        print()
        raise OSError(f"Connection closed early ({format_bytes(done)} of {format_bytes(total)}). "
                      "Run the download again to resume.")

    speed = (done - offset) / max(time.time() - started, 0.001)
    print("\r" + progress_line(done, total or done, speed).ljust(100))
    final_path = unique_path(final_path)
    os.replace(part_path, final_path)
    return final_path, done


def file_download():
    """Interactive file downloader (to be called from the menu)."""
    url = normalize_url(ask("Enter file URL: "))
    if not url:
        print("[!] Invalid URL.")
        return
    folder = ask("Save to folder [Enter = current folder]: ").strip('"') or os.getcwd()
    if not os.path.isdir(folder):
        if ask_yes(f"'{folder}' does not exist. Create it?"):
            try:
                os.makedirs(folder)
            except OSError as error:
                print(f"[!] Could not create the folder: {error}")
                return
        else:
            return

    print("\nDownloading (Ctrl+C to pause; run again to resume) ...")
    try:
        path, size = download(url, folder)
    except KeyboardInterrupt:
        print("\n[!] Paused. The partial file is kept so the next run can resume.")
        return
    except urllib.error.HTTPError as error:
        print(f"\n[!] The server answered {error.code} {error.reason}.")
        return
    except (urllib.error.URLError, OSError) as error:
        print(f"\n[!] Download failed: {getattr(error, 'reason', error)}")
        return
    print(f"\n[+] Saved: {path} ({format_bytes(size)})")
    print("[i] Verify important downloads with the Hash Generator (Security menu).")
