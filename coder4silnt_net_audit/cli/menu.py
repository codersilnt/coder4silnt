import ipaddress, os
from core.auditor import LocalNetworkAuditor
from core.defense import SERVICE_DEFENSE_NOTES

def _cidr():
    c = input("Target CIDR [Enter=auto]: ").strip()
    if c:
        ipaddress.ip_network(c, strict=False)
        return c
    return None

def opt1():
    try:
        c = _cidr()
        save = input("Save report? [y/N]: ").strip().lower() in {"y", "yes"}
        dns = input("Resolve hostnames? [y/N]: ").strip().lower() in {"y", "yes"}
        LocalNetworkAuditor(resolve_dns=dns).run_audit(c, True, save)
    except Exception as e:
        print(f"[!] {e}")

def opt2():
    try:
        c = _cidr()
        save = input("Save report? [y/N]: ").strip().lower() in {"y", "yes"}
        LocalNetworkAuditor(ports=[22, 80, 443, 554, 8080, 8443, 9100]).run_audit(c, True, save)
    except Exception as e:
        print(f"[!] {e}")

def opt3():
    info = LocalNetworkAuditor().detect_interfaces_and_routes()
    print(info)

def opt4():
    for p in sorted(SERVICE_DEFENSE_NOTES):
        s, t = SERVICE_DEFENSE_NOTES[p]
        print(f"{p:<4} | {s:<14} | {t}")

def opt5():
    LocalNetworkAuditor.diff_latest_reports("reports")

def run_cli():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Note: Non-root mode may limit ARP/ICMP visibility.")
    menu = {"1": opt1, "2": opt2, "3": opt3, "4": opt4, "5": opt5}
    while True:
        print("\n[1] Full Audit+Defense [2] Quick Web/IoT [3] Interface/Hotspot [4] Hardening [5] Diff [0] Exit")
        ch = input("Select [0-5]: ").strip()
        if ch == "0":
            break
        (menu.get(ch) or (lambda: print("Invalid selection.")))()
