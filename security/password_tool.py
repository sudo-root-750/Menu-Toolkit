import math
import secrets
import string

AMBIGUOUS = "O0oIl1|"  # characters that look alike
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

# Small built-in word list for passphrases (use a bigger list for more strength)
WORDS = [
    "apple", "river", "cloud", "tiger", "stone", "maple", "ocean", "falcon",
    "garden", "violet", "copper", "winter", "pencil", "rocket", "silver", "meadow",
    "lantern", "orange", "planet", "thunder", "bridge", "candle", "forest", "island",
    "marble", "pepper", "shadow", "summit", "velvet", "window", "yellow", "zephyr",
    "anchor", "breeze", "castle", "dragon", "ember", "harbor", "jungle", "kitten",
    "ladder", "magnet", "nectar", "orchid", "puzzle", "quartz", "ribbon", "saddle",
    "temple", "umbrella", "voyage", "walnut", "xylophone", "yogurt", "zigzag", "badger",
    "cactus", "dolphin", "eagle", "feather", "glacier", "hammer", "iceberg", "jasmine",
]


def ask_int(prompt, default, minimum, maximum):
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


def ask_yes(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({hint}): ").strip().lower()
    return default if not raw else raw == "y"


def build_password(length, use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous):
    """Build a random password that contains at least one char of each chosen type."""
    pools = []
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(SYMBOLS)

    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]

    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError("Length is too short for the selected types.")

    all_chars = "".join(pools)
    # One guaranteed char from each pool, the rest from all pools together
    chars = [secrets.choice(pool) for pool in pools]
    chars += [secrets.choice(all_chars) for _ in range(length - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars), len(all_chars)


def entropy_bits(length, pool_size):
    return length * math.log2(pool_size)


def strength_label(bits):
    if bits < 40:
        return "Very weak"
    if bits < 60:
        return "Weak"
    if bits < 80:
        return "Good"
    if bits < 110:
        return "Strong"
    return "Very strong"


def generate_password():
    length = ask_int("Length (8-128)", 16, 8, 128)
    if length is None:
        return

    use_lower = ask_yes("Lowercase letters?")
    use_upper = ask_yes("Uppercase letters?")
    use_digits = ask_yes("Digits?")
    use_symbols = ask_yes("Symbols?")
    avoid_ambiguous = ask_yes("Avoid look-alike characters (O,0,l,1,I)?", default=False)
    count = ask_int("How many passwords (1-10)", 1, 1, 10)
    if count is None:
        return

    try:
        print()
        for _ in range(count):
            password, pool_size = build_password(
                length, use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous
            )
            print(password)
    except ValueError as e:
        print(f"[!] {e}")
        return

    bits = entropy_bits(length, pool_size)
    print(f"\nStrength: {strength_label(bits)} (~{bits:.0f} bits)")


def generate_passphrase():
    count = ask_int("Number of words (3-10)", 5, 3, 10)
    if count is None:
        return
    separator = input("Separator [Enter = -]: ") or "-"
    capitalize = ask_yes("Capitalize words?", default=False)
    add_number = ask_yes("Add a number at the end?", default=True)

    words = [secrets.choice(WORDS) for _ in range(count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = separator.join(words)
    bits = count * math.log2(len(WORDS))
    if add_number:
        phrase += separator + str(secrets.randbelow(100))
        bits += math.log2(100)

    print(f"\n{phrase}")
    print(f"\nStrength: {strength_label(bits)} (~{bits:.0f} bits)")
    print("[i] The built-in list is small. For important accounts use a longer "
          "phrase or the random password option.")


def check_strength():
    password = input("Enter password to check: ")
    if not password:
        print("[!] Nothing entered.")
        return

    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32

    bits = entropy_bits(len(password), max(pool, 1))
    problems = []

    if len(password) < 12:
        problems.append("Shorter than 12 characters")
    if len(set(password)) < len(password) / 2:
        problems.append("Many repeated characters")
    if password.lower() in ("password", "12345678", "qwertyui", "iloveyou", "admin123"):
        problems.append("Very common password")
    lowered = password.lower()
    for seq in ("abcdef", "123456", "qwerty", "asdfgh", "654321"):
        if seq in lowered:
            problems.append(f"Contains a common sequence ('{seq}')")
            break
    if password.isalpha() or password.isdigit():
        problems.append("Uses only one character type")

    # Common patterns make the estimated entropy unrealistic
    if problems:
        bits = min(bits, 45)

    print(f"\nLength  : {len(password)}")
    print(f"Strength: {strength_label(bits)} (~{bits:.0f} bits)")
    if problems:
        print("\nProblems:")
        for p in problems:
            print(f"  [-] {p}")
    else:
        print("\n  [+] No obvious problems found.")
    print("\n[i] This is only an estimate. Never reuse a password across sites.")


def password_tool():
    """Password generator menu (to be called from the Security menu)."""
    while True:
        choice = input(
            "\nPassword Tool: \n > 1.random password \n > 2.passphrase"
            " \n > 3.check strength \n > 0.back \n>>>"
        ).strip()

        match choice:
            case "1":
                generate_password()
            case "2":
                generate_passphrase()
            case "3":
                check_strength()
            case "0":
                return
            case _:
                print("Invalid command. Try '1', '2', '3' or '0'.")