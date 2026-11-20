import ctypes
import json
import os
import platform
import socket
import subprocess
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None

SYSTEM = platform.system()

# Ports that are risky when reachable from the network
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "RPC", 139: "NetBIOS", 445: "SMB",
    3389: "RDP", 5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB",
}

# Result markers
MARKS = {"ok": "[+]", "warn": "[!]", "fail": "[-]", "info": "[i]"}


def run(cmd, timeout=15):
    """Run a command and return its output text, or None if it failed."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return (result.stdout or "") + (result.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        return None


# ---------- Individual checks: each returns (status, title, detail) ----------

def check_admin():
    try:
        if SYSTEM == "Windows":
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            is_admin = os.geteuid() == 0
    except Exception:
        return "info", "Admin rights", "Could not be determined"
    if is_admin:
        return "warn", "Admin rights", "Running as administrator/root (some checks are more complete, but avoid daily use)"
    return "ok", "Admin rights", "Running as a normal user"


def check_firewall():
    title = "Firewall"
    if SYSTEM == "Windows":
        out = run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if not out:
            return "info", title, "Could not read firewall state"
        states = [l.split()[-1].upper() for l in out.splitlines()
                  if l.strip().lower().startswith("state")]
        if not states:
            return "info", title, "Could not parse firewall state (non-English Windows?)"
        if all(s == "ON" for s in states):
            return "ok", title, f"Enabled on all {len(states)} profiles"
        return "fail", title, "Disabled on at least one profile (Domain/Private/Public)"
    if SYSTEM == "Darwin":
        out = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if out and "enabled" in out.lower():
            return "ok", title, "Application firewall is enabled"
        return "fail", title, "Application firewall is disabled"
    # Linux
    for svc in ("ufw", "firewalld", "nftables"):
        out = run(["systemctl", "is-active", svc])
        if out and out.strip() == "active":
            return "ok", title, f"{svc} is active"
    return "warn", title, "No active firewall service found (ufw / firewalld / nftables)"


def check_antivirus():
    title = "Antivirus (Defender)"
    if SYSTEM != "Windows":
        return None
    out = run(["powershell", "-NoProfile", "-Command",
               "Get-MpComputerStatus | Select-Object AntivirusEnabled,"
               "RealTimeProtectionEnabled,AntivirusSignatureAge | ConvertTo-Json"], timeout=30)
    if not out:
        return "info", title, "Could not query Defender (a third-party antivirus may be installed)"
    try:
        data = json.loads(out)
    except ValueError:
        return "info", title, "Defender not available (a third-party antivirus may be installed)"

    if not data.get("AntivirusEnabled") or not data.get("RealTimeProtectionEnabled"):
        return "fail", title, "Real-time protection is OFF"
    age = data.get("AntivirusSignatureAge")
    if isinstance(age, int) and age > 7:
        return "warn", title, f"Enabled, but virus definitions are {age} days old"
    return "ok", title, "Real-time protection is ON and definitions are up to date"


def read_registry(path, name, hive="HKLM"):
    import winreg
    root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
    with winreg.OpenKey(root, path) as key:
        return winreg.QueryValueEx(key, name)[0]


def check_uac():
    if SYSTEM != "Windows":
        return None
    try:
        value = read_registry(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    except OSError:
        return "info", "UAC", "Could not read the setting"
    if value == 1:
        return "ok", "UAC", "User Account Control is enabled"
    return "fail", "UAC", "User Account Control is disabled"


def check_rdp():
    if SYSTEM != "Windows":
        return None
    try:
        value = read_registry(r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    except OSError:
        return "info", "Remote Desktop", "Could not read the setting"
    if value == 0:
        return "warn", "Remote Desktop", "RDP is enabled (disable it if you do not need it)"
    return "ok", "Remote Desktop", "RDP is disabled"


def check_disk_encryption():
    title = "Disk encryption"
    if SYSTEM == "Windows":
        out = run(["manage-bde", "-status", "C:"])
        if not out or "administrator" in out.lower():
            return "info", title, "BitLocker status needs administrator rights"
        if "Protection On" in out:
            return "ok", title, "BitLocker is on for C:"
        if "Protection Off" in out:
            return "warn", title, "BitLocker is off for C:"
        return "info", title, "Could not determine BitLocker status"
    if SYSTEM == "Darwin":
        out = run(["fdesetup", "status"])
        if out and "On" in out:
            return "ok", title, "FileVault is on"
        return "warn", title, "FileVault is off"
    return "info", title, "Not checked on Linux (depends on LUKS setup)"


def check_ssh_config():
    """Linux/macOS: look for risky sshd settings (if the file is readable)."""
    if SYSTEM == "Windows":
        return None
    path = "/etc/ssh/sshd_config"
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = [l.strip().lower() for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        return None
    problems = []
    if "permitrootlogin yes" in lines:
        problems.append("root login allowed")
    if "passwordauthentication yes" in lines:
        problems.append("password login allowed")
    if problems:
        return "warn", "SSH server", ", ".join(problems)
    return "ok", "SSH server", "No risky settings found in sshd_config"


def exposed_ports_psutil():
    """Risky ports that listen on ALL interfaces (reachable from the network)."""
    exposed, local_only = [], []
    for c in psutil.net_connections(kind="inet"):
        if c.status != "LISTEN" or not c.laddr or c.laddr.port not in RISKY_PORTS:
            continue
        label = f"{c.laddr.port}/{RISKY_PORTS[c.laddr.port]}"
        if c.laddr.ip in ("127.0.0.1", "::1"):
            local_only.append(label)
        else:
            exposed.append(label)
    return sorted(set(exposed)), sorted(set(local_only))


def check_risky_ports():
    title = "Risky open ports"
    if psutil:
        try:
            exposed, local_only = exposed_ports_psutil()
            if exposed:
                return "warn", title, "Reachable from the network: " + ", ".join(exposed)
            note = f" (local only: {', '.join(local_only)})" if local_only else ""
            return "ok", title, "No risky port is exposed to the network" + note
        except psutil.AccessDenied:
            pass  # fall back to the simple test below

    # Fallback: try connecting to localhost (cannot tell local-only from exposed)
    found = []
    for port, name in RISKY_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        if sock.connect_ex(("127.0.0.1", port)) == 0:
            found.append(f"{port}/{name}")
        sock.close()
    if found:
        return "warn", title, "Listening: " + ", ".join(found) + " (install psutil to see if exposed)"
    return "ok", title, "No risky port is listening"


def check_updates():
    """Windows only: when the last hotfix was installed."""
    if SYSTEM != "Windows":
        return None
    title = "Windows updates"
    out = run(["powershell", "-NoProfile", "-Command",
               "(Get-HotFix | Sort-Object InstalledOn -Descending | "
               "Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd')"], timeout=40)
    if not out or not out.strip():
        return "info", title, "Could not read update history"
    try:
        last = datetime.strptime(out.strip().splitlines()[-1], "%Y-%m-%d")
    except ValueError:
        return "info", title, "Could not read update history"
    days = (datetime.now() - last).days
    if days > 60:
        return "warn", title, f"Last update was {days} days ago ({last:%Y-%m-%d})"
    return "ok", title, f"Last update was {days} days ago ({last:%Y-%m-%d})"


# ---------- Report ----------

CHECKS = [
    check_admin, check_firewall, check_antivirus, check_uac, check_rdp,
    check_disk_encryption, check_ssh_config, check_risky_ports, check_updates,
]


def security_audit():
    """Basic security audit of this computer (to be called from the Security menu)."""
    print(f"\nSecurity audit: {platform.system()} {platform.release()} ({socket.gethostname()})")
    print("This is read-only; nothing is changed on your system.\n")

    results = []
    for check in CHECKS:
        try:
            result = check()
        except Exception as e:  # one broken check must not stop the audit
            result = "info", check.__name__, f"Check failed: {e}"
        if result is None:
            continue
        results.append(result)
        status, title, detail = result
        print(f"{MARKS[status]} {title:<22} {detail}")

    counts = {s: sum(1 for r in results if r[0] == s) for s in MARKS}
    print(f"\nPassed: {counts['ok']} | Warnings: {counts['warn']} | "
          f"Problems: {counts['fail']} | Info: {counts['info']}")

    if counts["fail"]:
        print("\nFix the [-] items first, then the [!] items.")
    elif counts["warn"]:
        print("\nNo serious problem, but review the [!] items.")
    else:
        print("\nNo problem found in these basic checks.")
    print("[i] This is a basic check, not a full security assessment.")

    if input("\nSave report to a file? (y/n): ").strip().lower() == "y":
        name = f"security_audit_{datetime.now():%Y%m%d_%H%M%S}.txt"
        with open(name, "w", encoding="utf-8") as f:
            f.write(f"Security audit {datetime.now():%Y-%m-%d %H:%M}\n")
            for status, title, detail in results:
                f.write(f"{MARKS[status]} {title}: {detail}\n")
        print(f"[+] Report saved to {name}")