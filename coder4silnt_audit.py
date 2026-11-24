#!/usr/bin/env python3
import ipaddress
import os
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


SERVICE_DEFENSE_NOTES = {
    21: ("FTP", "Disable plain FTP; use SFTP/FTPS and enforce strong authentication."),
    22: ("SSH", "Use SSH keys, disable root login, and restrict access by IP."),
    23: ("Telnet", "Disable Telnet completely; use encrypted SSH instead."),
    53: ("DNS", "Restrict recursive queries to trusted clients and keep DNS patched."),
    80: ("HTTP", "Enforce HTTPS/TLS, update device firmware, and change default credentials."),
    135: ("MSRPC", "Block RPC exposure across untrusted segments via firewall rules."),
    139: ("NetBIOS", "Disable legacy NetBIOS/SMBv1 when unused and isolate internal traffic."),
    443: ("HTTPS", "Enforce modern TLS, maintain valid certs, and patch web services."),
    445: ("SMB", "Disable SMBv1, require SMB signing, and restrict share access."),
    554: ("RTSP", "Enforce strong auth, update IP camera/NVR firmware, and segment IoT."),
    1883: ("MQTT", "Enable TLS and authentication; block anonymous broker connections."),
    8080: ("HTTP-Alt", "Audit admin/proxy interfaces, restrict access, and apply updates."),
    8443: ("HTTPS-Alt", "Harden management portals and keep service packages current."),
    9100: ("JetDirect/Print", "Restrict network printers to authorized hosts and block external access."),
}


class LocalNetworkAuditor:
    def __init__(self, timeout: float = 0.5, workers: int = 110, max_hosts: int = 512):
        self.timeout = max(0.2, min(timeout, 3.0))
        self.workers = max(8, min(workers, 256))
        self.max_hosts = max(16, min(max_hosts, 4096))
        self.common_ports = sorted(SERVICE_DEFENSE_NOTES.keys())

    def run_cmd(self, cmd: list[str], cmd_timeout: float = 2.5) -> str:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=cmd_timeout,
                check=False,
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except Exception:
            return ""

    def _safe_24_cidr(self, ip_str: str) -> str:
        parts = ip_str.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    def detect_interfaces_and_routes(self) -> dict:
        info = {
            "gateway": None,
            "interface": None,
            "local_ip": None,
            "cidr": None,
            "hotspot_hint": False,
        }

        route_out = self.run_cmd(["ip", "route", "show"])
        for line in route_out.splitlines():
            gw_match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)", line)
            if gw_match and not info["gateway"]:
                info["gateway"] = gw_match.group(1)
                if not info["interface"]:
                    info["interface"] = gw_match.group(2)

            src_match = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+).*src\s+(\d+\.\d+\.\d+\.\d+)", line)
            if src_match:
                cidr_cand, iface_cand, ip_cand = src_match.group(1), src_match.group(2), src_match.group(3)
                try:
                    prefix_len = int(cidr_cand.split("/")[1])
                except Exception:
                    prefix_len = 24
                if iface_cand.startswith(("wlan", "ap", "swlan", "eth", "en", "br")):
                    info["interface"] = iface_cand
                    info["local_ip"] = ip_cand
                    info["cidr"] = self._safe_24_cidr(ip_cand) if prefix_len < 24 else cidr_cand
                    break
                if not info["cidr"]:
                    info["interface"] = iface_cand
                    info["local_ip"] = ip_cand
                    info["cidr"] = self._safe_24_cidr(ip_cand) if prefix_len < 24 else cidr_cand

        if not info["local_ip"]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(1.2)
                    sock.connect(("8.8.8.8", 80))
                    info["local_ip"] = sock.getsockname()[0]
                    info["cidr"] = self._safe_24_cidr(info["local_ip"])
            except Exception:
                pass

        if info["local_ip"] and info["local_ip"].startswith(("192.168.43.", "192.168.137.", "172.20.10.")):
            info["hotspot_hint"] = True

        addr_out = self.run_cmd(["ip", "addr", "show"])
        if re.search(r"(ap\d+|softap|swlan|wlan\d+_\d+|hotspot)", addr_out, re.IGNORECASE):
            info["hotspot_hint"] = True

        return info

    def parse_arp_table(self) -> dict[str, str]:
        ip_to_mac: dict[str, str] = {}

        try:
            with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as f:
                for line in f.read().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip_addr, mac_addr = parts[0].strip(), parts[3].strip().lower()
                        if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac_addr) and mac_addr != "00:00:00:00:00:00":
                            ip_to_mac[ip_addr] = mac_addr
        except Exception:
            pass

        for line in self.run_cmd(["ip", "neigh", "show"]).splitlines():
            m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\S+)", line.strip())
            if m and m.group(3).upper() not in {"FAILED", "INCOMPLETE"}:
                mac_val = m.group(2).lower()
                if mac_val != "00:00:00:00:00:00":
                    ip_to_mac[m.group(1)] = mac_val

        return ip_to_mac

    def ping_host(self, ip_str: str) -> bool:
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip_str]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip_str]
        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.4)
            return res.returncode == 0
        except Exception:
            return False

    def resolve_hostname(self, ip_str: str) -> str:
        try:
            return socket.gethostbyaddr(ip_str)[0]
        except Exception:
            return "-"

    def tcp_probe_port(self, ip_str: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip_str, port)) == 0
        except Exception:
            return False

    def scan_ports(self, ip_str: str) -> list[int]:
        open_ports = []
        with ThreadPoolExecutor(max_workers=min(12, len(self.common_ports))) as pool:
            future_map = {pool.submit(self.tcp_probe_port, ip_str, p): p for p in self.common_ports}
            for fut in as_completed(future_map):
                port = future_map[fut]
                try:
                    if fut.result():
                        open_ports.append(port)
                except Exception:
                    pass
        return sorted(open_ports)

    def audit_host(self, ip_str: str, known_mac: str | None, is_critical: bool = False) -> dict | None:
        alive = self.ping_host(ip_str)
        open_ports = self.scan_ports(ip_str) if (alive or is_critical) else []

        if not alive and not open_ports and not known_mac and not is_critical:
            return None

        return {
            "ip": ip_str,
            "mac": known_mac or "unknown",
            "hostname": self.resolve_hostname(ip_str),
            "open_ports": open_ports,
        }

    def run_audit(self, target_cidr: str | None = None, show_defense: bool = True) -> list[dict]:
        net_info = self.detect_interfaces_and_routes()
        raw_cidr = target_cidr or net_info["cidr"] or "192.168.1.0/24"

        try:
            network = ipaddress.ip_network(raw_cidr, strict=False)
        except ValueError as exc:
            print(f"[!] Invalid CIDR range '{raw_cidr}': {exc}")
            return []

        if network.prefixlen < 24 and not target_cidr:
            cidr = self._safe_24_cidr(net_info["local_ip"] or str(next(network.hosts(), "192.168.1.1")))
            network = ipaddress.ip_network(cidr, strict=False)
        else:
            cidr = str(network)

        print("=" * 74)
        print(f"[*] CODER4SILNT LAN/Hotspot Audit | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[*] Interface : {net_info['interface'] or 'auto'} | IP: {net_info['local_ip'] or 'unknown'} | Net: {cidr}")
        print(f"[*] Hotspot   : {'Yes' if net_info['hotspot_hint'] else 'No'}")
        print("=" * 74)

        hosts = [str(ip) for ip in network.hosts()][: self.max_hosts]
        arp_map = self.parse_arp_table()
        critical_ips = {ip for ip in (net_info["gateway"], net_info["local_ip"]) if ip}

        discovered = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {
                pool.submit(self.audit_host, h, arp_map.get(h), h in critical_ips): h
                for h in hosts
            }
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                    if res:
                        discovered.append(res)
                except Exception:
                    continue

        updated_arp = self.parse_arp_table()
        for item in discovered:
            if item["mac"] == "unknown" and item["ip"] in updated_arp:
                item["mac"] = updated_arp[item["ip"]]

        discovered.sort(key=lambda x: tuple(int(part) for part in x["ip"].split(".")))

        exposed_services_seen = set()
        print(f"\n[+] Discovered Hosts: {len(discovered)}")
        print("-" * 74)
        for entry in discovered:
            if entry["open_ports"]:
                svc_list = [f"{p}/{SERVICE_DEFENSE_NOTES[p][0]}" for p in entry["open_ports"]]
                exposed_services_seen.update(entry["open_ports"])
                ports_info = ", ".join(svc_list)
            else:
                ports_info = "none-common"
            print(f"{entry['ip']:<15} | {entry['mac']:<17} | Host:{entry['hostname']:<18} | {ports_info}")

        if show_defense:
            print("\n[+] Defensive Hardening Notes:")
            print("-" * 74)
            if exposed_services_seen:
                for port in sorted(exposed_services_seen):
                    svc_name, defense_tip = SERVICE_DEFENSE_NOTES[port]
                    print(f"Port {port:<4} ({svc_name:<12}): {defense_tip}")
            else:
                print("No common exposed service ports detected; keep firewall & firmware updated.")
        print("-" * 74)
        return discovered


def option_1_full_audit() -> None:
    try:
        cidr = input("Target CIDR [Enter=auto]: ").strip()
        if cidr:
            ipaddress.ip_network(cidr, strict=False)
        LocalNetworkAuditor(timeout=0.5, workers=110, max_hosts=512).run_audit(cidr or None, show_defense=True)
    except ValueError:
        print("[!] Invalid CIDR format.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as exc:
        print(f"[!] Error: {exc}")


def option_2_hosts_and_macs() -> None:
    try:
        cidr = input("Target CIDR [Enter=auto]: ").strip()
        if cidr:
            ipaddress.ip_network(cidr, strict=False)
        LocalNetworkAuditor(timeout=0.45, workers=120, max_hosts=512).run_audit(cidr or None, show_defense=False)
    except ValueError:
        print("[!] Invalid CIDR format.")
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
    except Exception as exc:
        print(f"[!] Error: {exc}")


def option_3_interface_info() -> None:
    info = LocalNetworkAuditor().detect_interfaces_and_routes()
    print("-" * 55)
    print(f"Interface : {info['interface'] or 'unknown'}")
    print(f"Local IP  : {info['local_ip'] or 'unknown'}")
    print(f"Gateway   : {info['gateway'] or 'unknown'}")
    print(f"CIDR      : {info['cidr'] or 'unknown'}")
    print(f"Hotspot   : {'Detected' if info['hotspot_hint'] else 'Not Detected'}")
    print("-" * 55)


def option_4_defense_guide() -> None:
    print("-" * 74)
    for port in sorted(SERVICE_DEFENSE_NOTES):
        svc, tip = SERVICE_DEFENSE_NOTES[port]
        print(f"{port:<4} | {svc:<14} | {tip}")
    print("-" * 74)


def main_menu() -> None:
    actions = {
        "1": option_1_full_audit,
        "2": option_2_hosts_and_macs,
        "3": option_3_interface_info,
        "4": option_4_defense_guide,
    }
    while True:
        print("\n=== CODER4SILNT NETWORK AUDIT ===")
        print("[1] Full LAN / Hotspot Audit + Defense Notes")
        print("[2] Fast Host & MAC Discovery")
        print("[3] Interface & Hotspot Detection")
        print("[4] Service Hardening Reference")
        print("[0] Exit")
        choice = input("Select [0-4]: ").strip()
        if choice == "0":
            break
        handler = actions.get(choice)
        if handler:
            handler()
        else:
            print("Invalid selection. Valid choices: 0-4.")


if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[!] Note: Running without root privileges; some ARP/ICMP details may be limited.")
    main_menu()
