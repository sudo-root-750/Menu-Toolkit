import base64
import codecs
import getpass
import hashlib
import os
import urllib.parse

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = None

SALT_SIZE = 16
MAX_FILE_MB = 200  # whole file is loaded in memory


# ---------- Core ----------

def derive_key(password, salt):
    """Turn a password + salt into a 32-byte Fernet key (scrypt)."""
    key = hashlib.scrypt(
        password.encode(), salt=salt,
        n=2**15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024,
    )
    return base64.urlsafe_b64encode(key)


def encrypt_bytes(data, password):
    """Return salt + encrypted token."""
    salt = os.urandom(SALT_SIZE)
    token = Fernet(derive_key(password, salt)).encrypt(data)
    return salt + token


def decrypt_bytes(blob, password):
    """Reverse of encrypt_bytes. Raises InvalidToken on wrong password."""
    salt, token = blob[:SALT_SIZE], blob[SALT_SIZE:]
    return Fernet(derive_key(password, salt)).decrypt(token)


def ask_password(confirm=False):
    """Ask for a password without showing it on screen."""
    password = getpass.getpass("Password: ")
    if not password:
        print("[!] Password cannot be empty.")
        return None
    if confirm and getpass.getpass("Repeat password: ") != password:
        print("[!] Passwords do not match.")
        return None
    return password


# ---------- Text ----------

def encrypt_text():
    text = input("Enter text to encrypt: ")
    if not text:
        print("[!] Nothing entered.")
        return
    password = ask_password(confirm=True)
    if password is None:
        return
    blob = encrypt_bytes(text.encode(), password)
    print("\nEncrypted text (copy all of it):")
    print(base64.urlsafe_b64encode(blob).decode())


def decrypt_text():
    cipher = input("Enter encrypted text: ").strip()
    password = ask_password()
    if password is None:
        return
    try:
        blob = base64.urlsafe_b64decode(cipher.encode())
        print("\nDecrypted text:")
        print(decrypt_bytes(blob, password).decode())
    except (InvalidToken, ValueError):
        print("[!] Wrong password or the text is damaged.")


# ---------- Files ----------

def read_file(path):
    path = path.strip().strip('"').strip("'")
    if not os.path.isfile(path):
        print("[!] File not found.")
        return None, None
    if os.path.getsize(path) > MAX_FILE_MB * 1024 * 1024:
        print(f"[!] File is larger than {MAX_FILE_MB} MB.")
        return None, None
    with open(path, "rb") as f:
        return path, f.read()


def confirm_overwrite(path):
    if os.path.exists(path):
        return input(f"'{path}' already exists. Overwrite? (y/n): ").strip().lower() == "y"
    return True


def encrypt_file():
    path, data = read_file(input("Enter file path: "))
    if path is None:
        return
    password = ask_password(confirm=True)
    if password is None:
        return
    out = path + ".enc"
    if not confirm_overwrite(out):
        print("Cancelled.")
        return
    with open(out, "wb") as f:
        f.write(encrypt_bytes(data, password))
    print(f"[+] Encrypted file saved: {out}")
    print("[i] The original file was NOT deleted.")


def decrypt_file():
    path, blob = read_file(input("Enter encrypted file path: "))
    if path is None:
        return
    password = ask_password()
    if password is None:
        return
    try:
        data = decrypt_bytes(blob, password)
    except (InvalidToken, ValueError):
        print("[!] Wrong password or the file is damaged.")
        return
    out = path[:-4] if path.endswith(".enc") else path + ".dec"
    if not confirm_overwrite(out):
        print("Cancelled.")
        return
    with open(out, "wb") as f:
        f.write(data)
    print(f"[+] Decrypted file saved: {out}")


# ---------- Encoding (NOT encryption) ----------

def encoding_menu():
    """Simple reversible encodings. Anyone can decode these, no password."""
    options = {
        "1": ("Base64 encode", lambda s: base64.b64encode(s.encode()).decode()),
        "2": ("Base64 decode", lambda s: base64.b64decode(s.encode(), validate=True).decode()),
        "3": ("Hex encode", lambda s: s.encode().hex()),
        "4": ("Hex decode", lambda s: bytes.fromhex(s).decode()),
        "5": ("URL encode", lambda s: urllib.parse.quote(s, safe="")),
        "6": ("URL decode", lambda s: urllib.parse.unquote(s)),
        "7": ("ROT13 (encode/decode)", lambda s: codecs.encode(s, "rot13")),
    }
    while True:
        print("\nEncoding (not secure, anyone can decode):")
        for key, (label, _) in options.items():
            print(f" > {key}.{label}")
        choice = input(" > 0.back \n>>>").strip()

        if choice == "0":
            return
        if choice not in options:
            print("Invalid command.")
            continue

        text = input("Enter text: ")
        try:
            print("\nResult:")
            print(options[choice][1](text))
        except (ValueError, UnicodeDecodeError):
            print("[!] Invalid input for this operation.")


# ---------- Menu ----------

def crypto_tool():
    """Encryption / decryption menu (to be called from the Security menu)."""
    while True:
        choice = input(
            "\nEncryption Tool: \n > 1.encrypt text \n > 2.decrypt text"
            " \n > 3.encrypt file \n > 4.decrypt file \n > 5.encoding (base64, hex, ...)"
            " \n > 0.back \n>>>"
        ).strip()

        if choice in ("1", "2", "3", "4") and Fernet is None:
            print("[!] cryptography is not installed. Run: pip install cryptography")
            continue

        match choice:
            case "1":
                encrypt_text()
            case "2":
                decrypt_text()
            case "3":
                encrypt_file()
            case "4":
                decrypt_file()
            case "5":
                encoding_menu()
            case "0":
                return
            case _:
                print("Invalid command. Try '1' to '5' or '0'.")