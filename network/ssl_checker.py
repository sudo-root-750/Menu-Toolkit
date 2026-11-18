import socket
import ssl
from datetime import datetime, timezone


def parse_target(raw):
    """Turn 'example.com', 'https://example.com/path' or 'example.com:8443' into (host, port)."""
    raw = raw.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]

    host, _, port = raw.partition(":")
    if not host:
        raise ValueError("Invalid host")
    return host, int(port) if port else 443


def fetch_certificate(host, port, timeout=10):
    """
    Connect with TLS and return (cert_dict, protocol, cipher, verify_error).
    First tries a normal verified connection. If verification fails
    (expired, self-signed, wrong host), it reconnects WITHOUT verification
    so we can still show what is wrong with the certificate.
    """
    # Attempt 1: verified connection
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(), tls.version(), tls.cipher(), None
    except ssl.SSLCertVerificationError as e:
        verify_error = e.verify_message

    # Attempt 2: unverified connection (only to read certificate details)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            cert = decode_der(der)
            return cert, tls.version(), tls.cipher(), verify_error


def decode_der(der):
    """Decode a binary certificate into the same dict format getpeercert() returns."""
    import tempfile, os
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        return ssl._ssl._test_decode_cert(path)
    finally:
        os.remove(path)


def name_to_dict(name_tuple):
    """Convert ((('commonName', 'x'),), ...) into {'commonName': 'x'}."""
    result = {}
    for group in name_tuple:
        for key, value in group:
            result[key] = value
    return result


def parse_cert_date(text):
    """Convert 'Jan  5 12:00:00 2027 GMT' into an aware datetime."""
    return datetime.strptime(text, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def print_report(host, port, cert, protocol, cipher, verify_error):
    subject = name_to_dict(cert.get("subject", ()))
    issuer = name_to_dict(cert.get("issuer", ()))

    not_before = parse_cert_date(cert["notBefore"])
    not_after = parse_cert_date(cert["notAfter"])
    days_left = (not_after - datetime.now(timezone.utc)).days

    print(f"\nHost            : {host}:{port}")
    print(f"Subject (CN)    : {subject.get('commonName', 'N/A')}")
    print(f"Organization    : {subject.get('organizationName', 'N/A')}")
    print(f"Issuer          : {issuer.get('organizationName', 'N/A')} ({issuer.get('commonName', 'N/A')})")
    print(f"Valid from      : {not_before:%Y-%m-%d %H:%M} UTC")
    print(f"Valid until     : {not_after:%Y-%m-%d %H:%M} UTC")
    print(f"Serial number   : {cert.get('serialNumber', 'N/A')}")
    print(f"TLS version     : {protocol}")
    print(f"Cipher          : {cipher[0]} ({cipher[2]} bit)")

    # Alternative names (domains covered by this certificate)
    sans = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if sans:
        print(f"Alt names ({len(sans)})  : {', '.join(sans[:8])}" + (" ..." if len(sans) > 8 else ""))

    # Status
    print("\nStatus:")
    if verify_error:
        print(f"  [-] Certificate NOT trusted: {verify_error}")
    else:
        print("  [+] Certificate is trusted and matches the hostname")

    if days_left < 0:
        print(f"  [-] EXPIRED {abs(days_left)} days ago")
    elif days_left <= 30:
        print(f"  [!] Expires soon: {days_left} days left")
    else:
        print(f"  [+] Valid for {days_left} more days")

    if protocol in ("TLSv1", "TLSv1.1"):
        print(f"  [-] Outdated protocol: {protocol}")
    else:
        print(f"  [+] Modern protocol: {protocol}")


def ssl_checker():
    """Interactive SSL certificate checker (to be called from the menu)."""
    raw = input("Enter Domain (e.g. example.com or example.com:8443): ").strip()
    if not raw:
        print("[!] Nothing entered.")
        return

    try:
        host, port = parse_target(raw)
    except ValueError:
        print("[!] Invalid domain or port.")
        return

    print(f"\nChecking certificate of {host}:{port} ...")
    try:
        cert, protocol, cipher, verify_error = fetch_certificate(host, port)
    except socket.gaierror:
        print(f"[!] Could not resolve '{host}'.")
        return
    except (TimeoutError, socket.timeout):
        print("[!] Connection timed out.")
        return
    except ssl.SSLError as e:
        print(f"[!] SSL error: {e}")
        return
    except OSError as e:
        print(f"[!] Connection error: {e}")
        return

    print_report(host, port, cert, protocol, cipher, verify_error)