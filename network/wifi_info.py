"""Wi-Fi Info: current connection, signal strength and nearby networks of THIS computer."""
import re

from network.common import IS_MAC, IS_WINDOWS, ask, ask_yes, run_cmd


def signal_text(percent):
    """Turn a 0-100 signal value into a label."""
    if percent >= 75:
        return "excellent"
    if percent >= 55:
        return "good"
    if percent >= 35:
        return "fair"
    return "weak"


def dbm_to_percent(dbm):
    """Rough conversion used by many tools: -50 dBm = 100%, -100 dBm = 0%."""
    return max(0, min(100, 2 * (dbm + 100)))


def parse_windows_interfaces(text):
    """Parse 'netsh wlan show interfaces' into a dict (first interface only)."""
    info = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = (p.strip() for p in line.split(":", 1))
        if key and key.lower() not in info:
            info[key.lower()] = value
    return info


def parse_windows_networks(text):
    """Parse 'netsh wlan show networks mode=bssid' into a list of dicts."""
    networks, current = [], None
    for line in text.splitlines():
        stripped = line.strip()
        ssid = re.match(r"SSID\s+\d+\s*:\s*(.*)", stripped)
        if ssid:
            current = {"ssid": ssid.group(1) or "(hidden)", "signal": 0, "auth": ""}
            networks.append(current)
        elif current is not None and ":" in stripped:
            key, value = (p.strip() for p in stripped.split(":", 1))
            if key.lower() == "authentication":
                current["auth"] = value
            elif key.lower() == "signal" and value.rstrip("%").isdigit():
                current["signal"] = max(current["signal"], int(value.rstrip("%")))
    return networks


def parse_nmcli_networks(text):
    """Parse 'nmcli -t -f IN-USE,SSID,SIGNAL,SECURITY dev wifi list' (colon separated, \\: escaped)."""
    networks = []
    for line in text.splitlines():
        fields = [f.replace("\x00", ":") for f in line.replace("\\:", "\x00").split(":")]
        if len(fields) < 4 or not fields[2].isdigit():
            continue
        networks.append({"ssid": fields[1] or "(hidden)", "signal": int(fields[2]),
                         "auth": fields[3] or "Open", "current": fields[0].strip() == "*"})
    return networks


def show_networks(networks):
    if not networks:
        print("  No networks found.")
        return
    merged = {}
    for n in networks:
        old = merged.get(n["ssid"])
        if old is None or n["signal"] > old["signal"]:
            merged[n["ssid"]] = n
    print(f"  {'NETWORK':<30}{'SIGNAL':<14}SECURITY")
    for n in sorted(merged.values(), key=lambda n: -n["signal"])[:25]:
        mark = "*" if n.get("current") else " "
        secure = n["auth"]
        warn = "  [!] open network" if secure.lower() in ("open", "none", "") else ""
        print(f" {mark}{n['ssid'][:28]:<30}{n['signal']:>3}% {signal_text(n['signal']):<8}{secure[:20]}{warn}")


def windows_info():
    out = run_cmd(["netsh", "wlan", "show", "interfaces"]) or ""
    info = parse_windows_interfaces(out)
    if not info or "ssid" not in info:
        print("[!] No Wi-Fi adapter found, or Wi-Fi is turned off.")
        return
    if info.get("state", "").lower() != "connected":
        print(f"Wi-Fi state: {info.get('state', 'unknown')} (not connected)")
    else:
        signal = int(info.get("signal", "0%").rstrip("%") or 0)
        print(f"Network     : {info.get('ssid', '?')}")
        print(f"Signal      : {signal}% ({signal_text(signal)})")
        for label, key in (("Band/Radio", "radio type"), ("Channel", "channel"),
                           ("Security", "authentication"), ("Cipher", "cipher"),
                           ("Rx speed", "receive rate (mbps)"), ("Tx speed", "transmit rate (mbps)")):
            if info.get(key):
                print(f"{label:<12}: {info[key]}")
    if ask_yes("\nShow nearby networks?", True):
        print("\nNearby networks:")
        show_networks(parse_windows_networks(run_cmd(["netsh", "wlan", "show", "networks", "mode=bssid"]) or ""))
    saved_passwords_windows()


def saved_passwords_windows():
    """Show the saved Wi-Fi password of one of YOUR OWN saved profiles (after confirmation)."""
    out = run_cmd(["netsh", "wlan", "show", "profiles"]) or ""
    profiles = [m.group(1).strip() for m in re.finditer(r":\s*(.+)$", out, re.M)
                if "profile" in m.string[max(0, m.start() - 40):m.start()].lower()]
    if not profiles:
        return
    if not ask_yes("\nShow the saved password of one of this computer's Wi-Fi profiles?"):
        return
    for number, name in enumerate(profiles, start=1):
        print(f"  {number}. {name}")
    choice = ask("Profile number: ")
    if not (choice.isdigit() and 1 <= int(choice) <= len(profiles)):
        print("[!] Invalid number.")
        return
    name = profiles[int(choice) - 1]
    details = run_cmd(["netsh", "wlan", "show", "profile", f"name={name}", "key=clear"]) or ""
    match = re.search(r"Key Content\s*:\s*(.+)", details)
    print(f"\nPassword of '{name}': {match.group(1).strip() if match else '(none stored / open network)'}")
    print("[i] This is stored on your own computer. Do not share it screen-recorded or in screenshots.")


def linux_info():
    out = run_cmd(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "dev", "wifi", "list"])
    if out is None:
        out_iw = run_cmd(["iwconfig"])
        if out_iw and "ESSID" in out_iw:
            print(out_iw.strip())
        else:
            print("[!] nmcli (NetworkManager) was not found, so Wi-Fi details are not available.")
        return
    networks = parse_nmcli_networks(out)
    if not networks:
        print("[!] No Wi-Fi adapter found, or Wi-Fi is turned off.")
        return
    current = next((n for n in networks if n.get("current")), None)
    if current:
        print(f"Network     : {current['ssid']}")
        print(f"Signal      : {current['signal']}% ({signal_text(current['signal'])})")
        print(f"Security    : {current['auth']}")
    else:
        print("Wi-Fi is not connected to any network.")
    print("\nNearby networks:")
    show_networks(networks)


def mac_info():
    airport = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
    out = run_cmd([airport, "-I"])
    if not out or "SSID" not in out:
        print("[!] Wi-Fi details are not available (newer macOS versions removed the 'airport' tool). "
              "Use the Wi-Fi menu or Option+click on the Wi-Fi icon.")
        return
    info = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in out.splitlines() if ":" in l)}
    print(f"Network     : {info.get('ssid', '?')}")
    rssi = info.get("agrctlrssi")
    if rssi and re.fullmatch(r"-?\d+", rssi):
        percent = dbm_to_percent(int(rssi))
        print(f"Signal      : {rssi} dBm ({signal_text(percent)})")
    print(f"Channel     : {info.get('channel', '?')}")
    print(f"Link speed  : {info.get('lasttxrate', '?')} Mbps")


def wifi_info():
    """Show Wi-Fi information of this computer (to be called from the menu)."""
    print()
    if IS_WINDOWS:
        windows_info()
    elif IS_MAC:
        mac_info()
    else:
        linux_info()
