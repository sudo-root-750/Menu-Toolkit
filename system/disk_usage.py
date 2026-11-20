import os
import shutil
import string
import platform


def format_bytes(size):
    """Convert bytes to a readable string (e.g. 8589934592 -> 8.00 GB)."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} PB"


def clean_path(raw):
    return raw.strip().strip('"').strip("'")


def ask_path():
    raw = clean_path(input("Enter folder path [Enter = current folder]: "))
    path = raw or os.getcwd()
    if not os.path.isdir(path):
        print("[!] Folder not found.")
        return None
    return os.path.abspath(path)


def bar(percent, width=20):
    filled = int(width * percent / 100)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


def get_drives():
    """Return the list of drive roots (C:\\, D:\\ on Windows, / on Linux/Mac)."""
    if platform.system() == "Windows":
        return [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
    return ["/"]


def show_drives():
    print(f"\n{'DRIVE':<10}{'TOTAL':<14}{'USED':<14}{'FREE':<14}USAGE")
    print("-" * 72)
    for drive in get_drives():
        try:
            usage = shutil.disk_usage(drive)
        except OSError:
            continue
        percent = usage.used / usage.total * 100 if usage.total else 0
        print(f"{drive:<10}{format_bytes(usage.total):<14}{format_bytes(usage.used):<14}"
              f"{format_bytes(usage.free):<14}{bar(percent)} {percent:.0f}%")


def scan_size(path, counter):
    """Return the total size of a folder (skips what cannot be read)."""
    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue  # avoid loops and double counting
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                            counter[0] += 1
                    except OSError:
                        continue
        except OSError:
            continue  # permission denied or folder vanished
    return total


def show_folder_sizes():
    path = ask_path()
    if path is None:
        return

    print(f"\nScanning {path} ...  (Ctrl+C to cancel)")
    sizes = []
    counter = [0]
    loose_files = 0

    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        sizes.append((entry.name, scan_size(entry.path, counter)))
                    elif entry.is_file(follow_symlinks=False):
                        loose_files += entry.stat(follow_symlinks=False).st_size
                        counter[0] += 1
                except OSError:
                    continue
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled.")
        return
    except PermissionError:
        print("[!] Access denied.")
        return

    if loose_files:
        sizes.append(("(files in this folder)", loose_files))
    if not sizes:
        print("Folder is empty.")
        return

    sizes.sort(key=lambda x: x[1], reverse=True)
    total = sum(s for _, s in sizes)

    print(f"\n{'FOLDER':<34}{'SIZE':<14}SHARE")
    print("-" * 66)
    for name, size in sizes[:20]:
        percent = size / total * 100 if total else 0
        print(f"{name[:32]:<34}{format_bytes(size):<14}{bar(percent, 15)} {percent:.0f}%")
    if len(sizes) > 20:
        print(f"... and {len(sizes) - 20} more")
    print(f"\nTotal: {format_bytes(total)} in {counter[0]:,} files")


def show_largest_files():
    path = ask_path()
    if path is None:
        return

    raw = input("How many files to show [Enter = 15]: ").strip()
    try:
        limit = int(raw) if raw else 15
    except ValueError:
        print("[!] Please enter a number.")
        return

    print(f"\nScanning {path} ...  (Ctrl+C to cancel)")
    files = []
    stack = [path]
    try:
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                files.append((entry.stat(follow_symlinks=False).st_size, entry.path))
                        except OSError:
                            continue
            except OSError:
                continue
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled. Showing partial results.")

    if not files:
        print("No files found.")
        return

    files.sort(reverse=True)
    print(f"\n{'SIZE':<14}PATH")
    print("-" * 70)
    for size, file_path in files[:limit]:
        print(f"{format_bytes(size):<14}{file_path}")
    print(f"\nFiles scanned: {len(files):,}")


def disk_usage():
    """Disk usage menu (to be called from the System menu)."""
    while True:
        choice = input(
            "\nDisk Usage: \n > 1.drives \n > 2.folder sizes"
            " \n > 3.largest files \n > 0.back \n>>>"
        ).strip()

        match choice:
            case "1":
                show_drives()
            case "2":
                show_folder_sizes()
            case "3":
                show_largest_files()
            case "0":
                return
            case _:
                print("Invalid command. Try '1', '2', '3' or '0'.")