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
        save = input("Save JSON/TXT/CSV report? [y/N]: ").strip().lower() in {"y", "yes"}
        LocalNetworkAuditor(grab_banner=True).run_audit(c, True, save)
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
    aud = LocalNetworkAuditor()
    info = aud.detect_interfaces_and_routes()
    conn = aud.connectivity_check(info.get("gateway"))
    chk = aud.self_check()
    print(f"IF:{info[\"interface\"]} IP:{info[\"local_ip\"]} GW:{info[\"gateway\"]} CIDR:{info[\"cidr\"]} Hotspot:{info[\"hotspot_hint\"]} DNS:{info[\"dns\"]}")
    print(f"Latency -> GW:{conn[\"gateway_ms\"]}ms | Internet:{conn[\"internet_ms\"]}ms | SelfCheck:{chk}")

def opt4():
    for p in sorted(SERVICE_DEFENSE_NOTES):
        s, t = SERVICE_DEFENSE_NOTES[p]
        print(f"{p:<4} | {s:<14} | {t}")

def opt5():
    q = input("Search IP / MAC / port in saved reports: ").strip()
    if q:
        LocalNetworkAuditor.search_reports(q, "reports")

def opt6():
    if input("Delete all saved reports in reports/? [y/N]: ").strip().lower() in {"y", "yes"}:
        LocalNetworkAuditor.clean_reports("reports")

def run_cli():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Note: Non-root mode may limit ARP/ICMP visibility.")
    menu = {"1": opt1, "2": opt2, "3": opt3, "4": opt4, "5": opt5, "6": opt6}
    while True:
        print("\n[1] Full Audit+Banner+Defense [2] Quick Web/IoT [3] Net/GW/SelfCheck [4] Hardening [5] Search Reports [6] Clean Reports [0] Exit")
        ch = input("Select [0-6]: ").strip()
        if ch == "0":
            break
        (menu.get(ch) or (lambda: print("Invalid selection.")))()
