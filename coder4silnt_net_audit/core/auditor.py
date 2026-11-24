import csv, ipaddress, json, platform, re, shutil, socket, subprocess, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from core.defense import SERVICE_DEFENSE_NOTES

class LocalNetworkAuditor:
    def __init__(self, timeout=0.5, workers=110, max_hosts=512, ports=None, grab_banner=True):
        self.timeout = max(0.2, min(timeout, 3.0))
        self.max_hosts = max(16, min(max_hosts, 4096))
        self.workers = max(8, min(workers, 256))
        self.common_ports = sorted(ports) if ports else sorted(SERVICE_DEFENSE_NOTES.keys())
        self.grab_banner = grab_banner

    def run_cmd(self, cmd, cmd_timeout=2.5):
        if not shutil.which(cmd[0]):
            return ""
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=cmd_timeout, check=False)
            return (p.stdout or "") + (p.stderr or "")
        except Exception:
            return ""

    def _safe_24_cidr(self, ip_str):
        parts = ip_str.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    def self_check(self):
        return {
            "ip_cmd": bool(shutil.which("ip")),
            "ping_cmd": bool(shutil.which("ping")),
            "proc_arp": Path("/proc/net/arp").exists(),
        }

    def detect_interfaces_and_routes(self):
        info = {"gateway": None, "interface": None, "local_ip": None, "cidr": None, "hotspot_hint": False, "dns": []}
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
        try:
            for line in Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip().startswith("nameserver"):
                    ns = line.split()[1].strip()
                    if ns not in info["dns"]:
                        info["dns"].append(ns)
        except Exception:
            pass
        return info

    def connectivity_check(self, gateway):
        res = {"gateway_ms": None, "internet_ms": None}
        if gateway:
            t0 = time.perf_counter()
            if self.ping_host(gateway):
                res["gateway_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        try:
            t1 = time.perf_counter()
            with socket.create_connection(("1.1.1.1", 53), timeout=1.5):
                res["internet_ms"] = round((time.perf_counter() - t1) * 1000, 1)
        except Exception:
            pass
        return res

    def parse_arp_table(self):
        macs = {}
        try:
            for line in Path("/proc/net/arp").read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
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

    def probe_port_banner(self, ip_str, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                if s.connect_ex((ip_str, port)) != 0:
                    return None
                banner = ""
                if self.grab_banner and port in {21, 22, 23, 80, 554, 8080}:
                    try:
                        s.settimeout(0.45)
                        if port in {80, 8080}:
                            s.sendall(b"HEAD / HTTP/1.0\r\nHost: local\r\n\r\n")
                        raw = s.recv(128)
                        clean = re.sub(r"[^\x20-\x7e]", " ", raw.decode("latin-1", errors="ignore")).strip()
                        banner = re.sub(r"\s+", " ", clean)[:60]
                    except Exception:
                        banner = ""
                return (port, banner)
        except Exception:
            return None

    def scan_ports(self, ip_str):
        open_map = {}
        with ThreadPoolExecutor(max_workers=min(12, max(1, len(self.common_ports)))) as pool:
            fmap = {pool.submit(self.probe_port_banner, ip_str, p): p for p in self.common_ports}
            for fut in as_completed(fmap):
                try:
                    res = fut.result()
                    if res:
                        open_map[res[0]] = res[1]
                except Exception:
                    pass
        return {p: open_map[p] for p in sorted(open_map)}

    def audit_host(self, ip_str, known_mac, is_critical=False):
        alive = self.ping_host(ip_str)
        ports_dict = self.scan_ports(ip_str) if (alive or is_critical) else {}
        if not alive and not ports_dict and not known_mac and not is_critical:
            return None
        return {"ip": ip_str, "mac": known_mac or "unknown", "open_ports": ports_dict}

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
        print("=" * 76)
        print(f"[*] CODER4SILNT Audit | {ts} | IF:{info[\"interface\"] or \"auto\"} | IP:{info[\"local_ip\"] or \"unknown\"} | Net:{cidr}")
        print("=" * 76)
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
        lines = [f"\n[+] Hosts: {len(found)}", "-" * 76]
        for h in found:
            p_items = []
            for p, b in h["open_ports"].items():
                seen_ports.add(p)
                p_items.append(f"{p}/{SERVICE_DEFENSE_NOTES[p][0]}" + (f"[{b}]" if b else ""))
            lines.append(f"{h[\"ip\"]:<15} | {h[\"mac\"]:<17} | {\", \".join(p_items) if p_items else \"none-common\"}")
        def_notes = []
        if show_defense:
            lines.append("\n[+] Defense Notes:")
            lines.append("-" * 76)
            for p in sorted(seen_ports):
                sn, dt = SERVICE_DEFENSE_NOTES[p]
                def_notes.append({"port": p, "service": sn, "defense": dt})
                lines.append(f"Port {p:<4} ({sn:<12}): {dt}")
            if not seen_ports:
                lines.append("No common exposed ports detected; keep firewall & firmware updated.")
        lines.append("-" * 76)
        txt_out = "\n".join(lines)
        print(txt_out)
        rep = {"meta": {"timestamp": ts, "cidr": cidr, "hotspot": bool(info["hotspot_hint"])}, "hosts": found, "defense_notes": def_notes}
        if save_report:
            od = Path(reports_dir)
            od.mkdir(parents=True, exist_ok=True)
            tag = datetime.now().strftime("%Y%m%d_%H%M%S")
            (od / f"audit_{tag}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
            (od / f"audit_{tag}.txt").write_text(txt_out.lstrip() + "\n", encoding="utf-8")
            with (od / f"audit_{tag}.csv").open("w", newline="", encoding="utf-8") as cf:
                w = csv.writer(cf)
                w.writerow(["ip", "mac", "ports_banners"])
                for h in found:
                    pb = "; ".join(f"{k}:{v}" for k, v in h["open_ports"].items())
                    w.writerow([h["ip"], h["mac"], pb])
            print(f"[+] Saved: {reports_dir}/audit_{tag}.(json|txt|csv)")
        return rep

    @staticmethod
    def search_reports(term, reports_dir="reports"):
        q = term.strip().lower()
        files = sorted(Path(reports_dir).glob("audit_*.json"))
        if not files:
            print("[!] No saved JSON reports found in reports/.")
            return
        hits = 0
        for fp in files:
            data = json.loads(fp.read_text(encoding="utf-8"))
            for h in data.get("hosts", []):
                blob = f"{h.get(\"ip\",\"\")} {h.get(\"mac\",\"\")} {h.get(\"open_ports\",\"\")}".lower()
                if q in blob:
                    hits += 1
                    print(f"[{fp.name}] {h.get(\"ip\")} | {h.get(\"mac\")} | Ports: {h.get(\"open_ports\")}")
        print(f"[+] Search matches: {hits}")

    @staticmethod
    def clean_reports(reports_dir="reports"):
        files = list(Path(reports_dir).glob("audit_*.*"))
        for f in files:
            f.unlink(missing_ok=True)
        print(f"[+] Removed {len(files)} report files from {reports_dir}/.")
