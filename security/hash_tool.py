import hashlib
import hmac
import os

ALGORITHMS = ["md5", "sha1", "sha256", "sha512"]
CHUNK_SIZE = 1024 * 1024  # read big files 1 MB at a time


def hash_text_value(text, algorithm):
    return hashlib.new(algorithm, text.encode()).hexdigest()


def hash_file_value(path, algorithm):
    """Hash a file in chunks, so even huge files do not fill the memory."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
    return h.hexdigest()


def clean_path(raw):
    return raw.strip().strip('"').strip("'")


def hash_text():
    text = input("Enter text: ")
    if not text:
        print("[!] Nothing entered.")
        return
    print()
    for algo in ALGORITHMS:
        print(f"{algo.upper():<8}: {hash_text_value(text, algo)}")


def hash_file():
    path = clean_path(input("Enter file path: "))
    if not os.path.isfile(path):
        print("[!] File not found.")
        return
    print(f"\nHashing {os.path.basename(path)} ({os.path.getsize(path) / 1024 / 1024:.2f} MB) ...\n")
    try:
        for algo in ALGORITHMS:
            print(f"{algo.upper():<8}: {hash_file_value(path, algo)}")
    except PermissionError:
        print("[!] Access denied.")
    except OSError as e:
        print(f"[!] Could not read file: {e}")


def detect_algorithm(expected):
    """Guess the algorithm from the hash length."""
    lengths = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    return lengths.get(len(expected))


def verify_file():
    path = clean_path(input("Enter file path: "))
    if not os.path.isfile(path):
        print("[!] File not found.")
        return

    expected = input("Enter the official hash: ").strip().lower()
    algo = detect_algorithm(expected)
    if algo is None:
        print("[!] Unknown hash length (expected 32, 40, 64 or 128 characters).")
        return

    print(f"\nAlgorithm detected: {algo.upper()}\nCalculating ...")
    try:
        actual = hash_file_value(path, algo)
    except OSError as e:
        print(f"[!] Could not read file: {e}")
        return

    print(f"\nExpected: {expected}")
    print(f"Actual  : {actual}")
    if hmac.compare_digest(actual, expected):
        print("\n[+] MATCH: the file is intact.")
    else:
        print("\n[-] MISMATCH: the file is damaged or has been modified!")


def hash_tool():
    """Hash generator menu (to be called from the Security menu)."""
    while True:
        choice = input(
            "\nHash Generator: \n > 1.hash text \n > 2.hash file"
            " \n > 3.verify file \n > 0.back \n>>>"
        ).strip()

        match choice:
            case "1":
                hash_text()
            case "2":
                hash_file()
            case "3":
                verify_file()
            case "0":
                return
            case _:
                print("Invalid command. Try '1', '2', '3' or '0'.")