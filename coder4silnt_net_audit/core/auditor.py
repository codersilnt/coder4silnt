import ipaddress, json, platform, re, socket, subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from core.defense import SERVICE_DEFENSE_NOTES

class LocalNetworkAuditor:
    def __init__(self, timeout=0.5, workers=110, max_hosts=512, ports=None, resolve_dns=False, dns_timeout=0.4):
        self.timeout = max(0.2, min(timeout, 3.0))
        self.max_hosts = max(16, min(max_hosts, 4096))
        self.workers = max(8, min(workers, 256))
        self.common_ports = sorted(ports) if ports else sorted(SERVICE_DEFENSE_NOTES.keys())
        self.resolve_dns = resolve_dns
        self.dns_timeout = max(0.1, min(dns_timeout, 2.0))

    def run_cmd(self, cmd, cmd_timeout=2.5):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=cmd_timeout, check=False)
            return (p.stdout or "") + (p.stderr or "")
        except Exception:
            return ""

    def _safe_24_cidr(self, ip_str):
        parts = ip_str.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    def detect_interfaces_and_routes(self):
        info = {"gateway": None, "interface": None, "local_ip": None, "cidr": None, "hotspot_hint": False}
        for line in self.run_cmd(["ip", "route", "show"]).splitlines():
            gw = re.search(r"default via (\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)", line)
            if gw and not info["gateway"]:
                info["gateway"] = gw.group(1)
                if not info["interface"]:
                    info["interface"] = gw.group(2)
            src = re.search(r"(\d+\.\d+\.\d+\.\d+/\d+)\s+dev\s+(\S+).*src\s+(\d+\.\d+\.\d+\.\d+)", line)
            if src:
                c_cidr, iface, ip_c = src.group(1), src.group(2), src.group(3)
                pref = int(c_cidr.split("/")[1]) if "/" in c_cidr else 24
                if iface.startswith(("wlan", "ap", "swlan", "eth", "en", "br")):
                    info.update({"interface": iface, "local_ip": ip_c, "cidr": self._safe_24_cidr(ip_c) if pref < 24 else c_cidr})
                    break
                if not info["cidr"]:
                    info.update({"interface": iface, "local_ip": ip_c, "cidr": self._safe_24_cidr(ip_c) if pref < 24 else c_cidr})
        if not info["local_ip"]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(1.2)
                    s.connect(("8.8.8.8", 80))
                    info["local_ip"] = s.getsockname()[0]
                    info["cidr"] = self._safe_24_cidr(info["local_ip"])
            except Exception:
                pass
        if info["local_ip"] and info["local_ip"].startswith(("192.168.43.", "192.168.137.", "172.20.10.")):
            info["hotspot_hint"] = True
        if re.search(r"(ap\d+|softap|swlan|wlan\d+_\d+|hotspot)", self.run_cmd(["ip", "addr", "show"]), re.I):
            info["hotspot_hint"] = True
        return info

    def parse_arp_table(self):
        macs = {}
        try:
            with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as f:
                for line in f.read().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip_a, m_a = parts[0].strip(), parts[3].strip().lower()
                        if re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", m_a) and m_a != "00:00:00:00:00:00":
                            macs[ip_a] = m_a
        except Exception:
            pass
        for line in self.run_cmd(["ip", "neigh", "show"]).splitlines():
            m = re.search(r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\S+)", line.strip())
            if m and m.group(3).upper() not in {"FAILED", "INCOMPLETE"} and m.group(2).lower() != "00:00:00:00:00:00":
                macs[m.group(1)] = m.group(2).lower()
        return macs

    def ping_host(self, ip_str):
        cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip_str] if platform.system().lower() == "windows" else ["ping", "-c", "1", "-W", "1", ip_str]
        try:
            return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.4).returncode == 0
        except Exception:
            return False

    def resolve_hostname(self, ip_str):
        if not self.resolve_dns:
            return "-"
        old_t = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.dns_timeout)
            return socket.gethostbyaddr(ip_str)[0]
        except Exception:
            return "-"
        finally:
            socket.setdefaulttimeout(old_t)

    def tcp_probe_port(self, ip_str, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip_str, port)) == 0
        except Exception:
            return False

    def scan_ports(self, ip_str):
        open_p = []
        with ThreadPoolExecutor(max_workers=min(12, max(1, len(self.common_ports)))) as pool:
            fmap = {pool.submit(self.tcp_probe_port, ip_str, p): p for p in self.common_ports}
            for fut in as_completed(fmap):
                try:
                    if fut.result():
                        open_p.append(fmap[fut])
                except Exception:
                    pass
        return sorted(open_p)

    def audit_host(self, ip_str, known_mac, is_critical=False):
        alive = self.ping_host(ip_str)
        ports = self.scan_ports(ip_str) if (alive or is_critical) else []
        if not alive and not ports and not known_mac and not is_critical:
            return None
        return {"ip": ip_str, "mac": known_mac or "unknown", "hostname": self.resolve_hostname(ip_str), "open_ports": ports}

    def run_audit(self, target_cidr=None, show_defense=True, save_report=False, reports_dir="reports"):
        info = self.detect_interfaces_and_routes()
        raw = target_cidr or info["cidr"] or "192.168.1.0/24"
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as e:
            print(f"[!] Invalid CIDR: {e}")
            return {"meta": {}, "hosts": []}
        cidr = self._safe_24_cidr(info["local_ip"] or "192.168.1.1") if (net.prefixlen < 24 and not target_cidr) else str(net)
        net = ipaddress.ip_network(cidr, strict=False)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print("=" * 74)
        print(f"[*] CODER4SILNT Audit | {ts} | IF:{info[\"interface\"] or \"auto\"} | IP:{info[\"local_ip\"] or \"unknown\"} | Net:{cidr}")
        print("=" * 74)
        hosts = [str(ip) for ip in net.hosts()][: self.max_hosts]
        workers = min(self.workers, max(8, len(hosts) // 2)) if hosts else 8
        arp_map = self.parse_arp_table()
        crit = {x for x in (info["gateway"], info["local_ip"]) if x}
        found, done, total = [], 0, len(hosts)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self.audit_host, h, arp_map.get(h), h in crit): h for h in hosts}
            for fut in as_completed(futs):
                done += 1
                if total >= 32 and (done % max(1, total // 5) == 0 or done == total):
                    print(f"[~] Progress: {int(done * 100 / total)}% ({done}/{total})", end="\r", flush=True)
                try:
                    r = fut.result()
                    if r:
                        found.append(r)
                except Exception:
                    continue
        if total >= 32:
            print()
        upd_arp = self.parse_arp_table()
        for item in found:
            if item["mac"] == "unknown" and item["ip"] in upd_arp:
                item["mac"] = upd_arp[item["ip"]]
        found.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
        seen_ports = set()
        lines = [f"\n[+] Hosts: {len(found)}", "-" * 74]
        for h in found:
            s_list = [f"{p}/{SERVICE_DEFENSE_NOTES[p][0]}" for p in h["open_ports"]]
            seen_ports.update(h["open_ports"])
            lines.append(f"{h[\"ip\"]:<15} | {h[\"mac\"]:<17} | Host:{h[\"hostname\"]:<16} | {\", \".join(s_list) if s_list else \"none-common\"}")
        def_notes = []
        if show_defense:
            lines.append("\n[+] Defense Notes:")
            lines.append("-" * 74)
            for p in sorted(seen_ports):
                sn, dt = SERVICE_DEFENSE_NOTES[p]
                def_notes.append({"port": p, "service": sn, "defense": dt})
                lines.append(f"Port {p:<4} ({sn:<12}): {dt}")
            if not seen_ports:
                lines.append("No common exposed ports detected; keep firewall & firmware updated.")
        lines.append("-" * 74)
        txt_out = "\n".join(lines)
        print(txt_out)
        rep = {"meta": {"timestamp": ts, "cidr": cidr, "hotspot": bool(info["hotspot_hint"])}, "hosts": found, "defense_notes": def_notes}
        if save_report:
            od = Path(reports_dir)
            od.mkdir(parents=True, exist_ok=True)
            tag = datetime.now().strftime("%Y%m%d_%H%M%S")
            (od / f"audit_{tag}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
            (od / f"audit_{tag}.txt").write_text(txt_out.lstrip() + "\n", encoding="utf-8")
            print(f"[+] Saved to {reports_dir}/audit_{tag}.(json|txt)")
        return rep

    @staticmethod
    def diff_latest_reports(reports_dir="reports"):
        files = sorted(Path(reports_dir).glob("audit_*.json"))
        if len(files) < 2:
            print("[!] Need at least 2 saved JSON reports in reports/ to diff.")
            return
        p1, p2 = json.loads(files[-2].read_text(encoding="utf-8")), json.loads(files[-1].read_text(encoding="utf-8"))
        m1, m2 = {x["ip"]: x for x in p1.get("hosts", [])}, {x["ip"]: x for x in p2.get("hosts", [])}
        add_ips = sorted(set(m2) - set(m1), key=lambda ip: tuple(int(k) for k in ip.split(".")))
        rem_ips = sorted(set(m1) - set(m2), key=lambda ip: tuple(int(k) for k in ip.split(".")))
        print(f"Diff {files[-2].name} -> {files[-1].name} | +New: {add_ips or \"none\"} | -Left: {rem_ips or \"none\"}")
