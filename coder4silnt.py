#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[38;5;45m"
BLUE = "\033[38;5;33m"
GOLD = "\033[38;5;214m"
RED = "\033[38;5;196m"
GREEN = "\033[38;5;46m"
MAGENTA = "\033[38;5;141m"
DIM = "\033[38;5;245m"

ALPHA_BANNER = r"""
     _    _     ____  _   _    _       _____ _____    _    __  __
    / \  | |   |  _ \| | | |  / \     |_   _| ____|  / \  |  \/  |
   / _ \ | |   | |_) | |_| | / _ \      | | |  _|   / _ \ | |\/| |
  / ___ \| |___|  __/|  _  |/ ___ \     | | | |___ / ___ \| |  | |
 /_/   \_\_____|_|   |_| |_/_/   \_\    |_| |_____/_/   \_\_|  |_|
"""

SECURITY_HEADERS = {
    "content-security-policy": ("Missing Content-Security-Policy header", "HIGH"),
    "strict-transport-security": ("Missing Strict-Transport-Security (HSTS) header", "HIGH"),
    "x-frame-options": ("Missing X-Frame-Options header", "MEDIUM"),
    "x-content-type-options": ("Missing X-Content-Type-Options header", "MEDIUM"),
    "referrer-policy": ("Missing Referrer-Policy header", "LOW"),
    "permissions-policy": ("Missing Permissions-Policy header", "LOW"),
    "cross-origin-opener-policy": ("Missing Cross-Origin-Opener-Policy header", "LOW"),
    "cross-origin-resource-policy": ("Missing Cross-Origin-Resource-Policy header", "LOW"),
}

COMMON_PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443)
EXTERNAL_TOOLS = ("python3", "curl", "dig", "nmap", "whois", "host", "nslookup", "openssl")
FINANCE_DIR = Path("/root/finance_reports")
PHONE_DOWNLOAD_DIRS = [
    Path("/sdcard/Download"),
    Path("/storage/emulated/0/Download"),
]

COUNTRY_PREFIXES = {
    "+1": "US / Canada / NANP",
    "+7": "Russia / Kazakhstan",
    "+20": "Egypt",
    "+27": "South Africa",
    "+33": "France",
    "+34": "Spain",
    "+39": "Italy",
    "+44": "United Kingdom",
    "+49": "Germany",
    "+60": "Malaysia",
    "+62": "Indonesia",
    "+90": "Turkey",
    "+91": "India",
    "+92": "Pakistan",
    "+212": "Morocco",
    "+213": "Algeria",
    "+216": "Tunisia",
    "+218": "Libya",
    "+249": "Sudan",
    "+961": "Lebanon",
    "+962": "Jordan",
    "+963": "Syria",
    "+964": "Iraq",
    "+965": "Kuwait",
    "+966": "Saudi Arabia",
    "+967": "Yemen",
    "+968": "Oman",
    "+970": "Palestine",
    "+971": "United Arab Emirates",
    "+973": "Bahrain",
    "+974": "Qatar",
}

EGYPT_PREFIX_HINTS = {
    "+2010": "Egypt Mobile (Vodafone prefix)",
    "+2011": "Egypt Mobile (e& / Etisalat prefix)",
    "+2012": "Egypt Mobile (Orange prefix)",
    "+2015": "Egypt Mobile (WE prefix)",
    "+202": "Egypt Landline (Greater Cairo)",
    "+203": "Egypt Landline (Alexandria)",
    "+2082": "Egypt Landline (Beni Suef)",
}


def get_term_width() -> int:
    try:
        return max(56, shutil.get_terminal_size((80, 24)).columns)
    except Exception:
        return 80


def save_audit_report(category: str, target: str, findings: dict) -> str:
    import json, re, time
    from pathlib import Path
    out_dir = Path("/root/coder4silnt-reports")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", target.strip())[:40] or "target"
    base_name = f"{category}_{safe_target}_{ts}"
    payload = {"timestamp": ts, "category": category, "target": target, "mode": "non-intrusive-posture-audit", "findings": findings}
    json_file = out_dir / f"{base_name}.json"
    txt_file = out_dir / f"{base_name}.txt"
    json_file.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    lines = ["CODER4SILNT AUDIT REPORT", f"Timestamp : {ts}", f"Category  : {category}", f"Target    : {target}", "-" * 44]
    for k, v in findings.items():
        lines.append(f"{k}: {v}")
    txt_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(txt_file)

def inspect_apk_summary(apk_path_str: str) -> dict:
    import zipfile
    from pathlib import Path
    apk_path = Path(apk_path_str.strip())
    if not apk_path.is_file():
        return {"error": f"APK file not found: {apk_path}"}
    summary = {"file_size_bytes": apk_path.stat().st_size, "entries_count": 0, "has_manifest": False, "has_classes_dex": False, "suspicious_keywords_in_names": []}
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = zf.namelist()
            summary["entries_count"] = len(names)
            summary["has_manifest"] = "AndroidManifest.xml" in names
            summary["has_classes_dex"] = any(n.startswith("classes") and n.endswith(".dex") for n in names)
            toks = ("config", "secret", "debug", "test", "cert")
            summary["suspicious_keywords_in_names"] = [n for n in names if any(t in n.lower() for t in toks)][:15]
    except Exception as exc:
        summary["archive_error"] = str(exc)
    return summary


def _coder4silnt_post_scan_hook(choice: str, target: str = "", extra: dict | None = None) -> None:
    c = str(choice).strip()
    if c not in ("5", "6"):
        return
    findings = {"status": "completed", "option": c}
    if extra and isinstance(extra, dict):
        findings.update(extra)
    t = (target or "").strip()
    if c == "5" and t.lower().endswith(".apk"):
        findings["apk_summary"] = inspect_apk_summary(t)
    try:
        saved_path = save_audit_report(f"opt_{c}", t or "local_scan", findings)
        print(f"\n[+] Report saved: {saved_path}")
    except Exception as exc:
        print(f"\n[!] Report save note: {exc}")

def print_alpha_header() -> None:
    import base64
    e = chr(27)
    b, bl, c, w, g, r = e + "[1m", e + "[94m", e + "[96m", e + "[97m", e + "[93m", e + "[0m"
    art = base64.b64decode("ICBfX18gIF9fXyAgX19fICBfX18gIF9fXyAgXyBfICAgX19fICBfX18gIF8gICAgXyAgXyAgX19fX18KIC8gX198LyBfIFx8ICAgXHwgX198fCBfIFx8IHwgfCAvIF9ffHxfIF98fCB8ICB8IFx8IHx8XyAgIF98CnwgKF9fKCAoXykgfCB8KSB8IF98IHwgICAvXF8gIF98XF9fIFwgfCB8IHwgfF9ffCAuYCB8ICB8IHwKIFxfX198XF9fXy98X19fL3xfX198fF98X1wgIHxffCB8X19fL3xfX198fF9fX198X3xcX3wgIHxffA==").decode("utf-8")
    print(b + bl + art + r)
    print(b + g + "         >>>  A L P H A   T E A M  <<<" + r)
    print(b + c + "     [ RECON - POSTURE - OSINT - AUDIT ]" + r)
    print()


def sanitize_query_name(query_label: str) -> str:
    cleaned = query_label.strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'[\\/:*?"<>|\s]+', "_", cleaned).strip("._-")
    return cleaned or "alpha_scan_target"


def inspect_system_tools() -> dict:
    inventory = []
    for tool in EXTERNAL_TOOLS:
        path = shutil.which(tool)
        if not path:
            inventory.append({"tool": tool, "installed": False, "path": None, "info": "Not installed"})
            continue
        info = "Available"
        try:
            if tool in ("python3", "curl", "nmap"):
                proc = subprocess.run([tool, "--version"], capture_output=True, text=True, timeout=4)
                info = (proc.stdout or proc.stderr or "Available").strip().splitlines()[0]
            elif tool == "dig":
                proc = subprocess.run([tool, "-v"], capture_output=True, text=True, timeout=4)
                info = (proc.stdout or proc.stderr or "Available").strip().splitlines()[0]
            elif tool == "openssl":
                proc = subprocess.run([tool, "version"], capture_output=True, text=True, timeout=4)
                info = (proc.stdout or "Available").strip().splitlines()[0]
        except Exception:
            info = "Available"
        inventory.append({"tool": tool, "installed": True, "path": path, "info": info})

    installed_count = sum(1 for item in inventory if item["installed"])
    return {
        "installed_count": installed_count,
        "total_checked": len(inventory),
        "tools": inventory,
    }


def run_optional_nmap_summary(host: str, enabled: bool) -> dict:
    if not enabled:
        return {"enabled": False, "status": "Not requested", "services": []}
    if not host:
        return {"enabled": True, "status": "No target host provided", "services": []}
    if not shutil.which("nmap"):
        return {"enabled": True, "status": "nmap binary not installed", "services": []}

    ports_arg = ",".join(str(p) for p in COMMON_PORTS)
    cmd = ["nmap", "-Pn", "-T4", "--host-timeout", "18s", "-p", ports_arg, host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=22)
        out = proc.stdout or ""
        services = []
        for ln in out.splitlines():
            m = re.match(r"^(\d+/\w+)\s+(open|filtered)\s+([^\s]+)(?:\s+(.*))?$", ln.strip())
            if m and m.group(2) == "open":
                services.append({
                    "port_proto": m.group(1),
                    "service": m.group(3),
                    "version": (m.group(4) or "").strip(),
                })
        return {
            "enabled": True,
            "status": "Completed",
            "services": services,
        }
    except Exception as exc:
        return {"enabled": True, "status": f"Error: {exc}", "services": []}


def run_dig_query(qtype: str, name: str, timeout_sec: int = 12) -> tuple:
    if not shutil.which("dig"):
        return [], None
    servers = [None, "@8.8.8.8", "@1.1.1.1"]
    last_err = None
    for srv in servers:
        cmd = ["dig", "+time=4", "+tries=2", "+short"]
        if srv:
            cmd.append(srv)
        cmd.extend([qtype, name])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
            lines = [ln.strip().strip('"') for ln in (proc.stdout or "").splitlines() if ln.strip()]
            if lines:
                return lines, None
        except Exception as exc:
            last_err = f"dig {qtype} {name} ({srv or 'default'}): {exc}"
    return [], last_err


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def extract_host(target: str) -> str:
    return (urlparse(normalize_url(target)).hostname or target.strip()).lower()


def analyze_cookies_deep(raw_headers: list, is_https: bool) -> tuple:
    cookies = []
    findings = []
    for k, v in raw_headers:
        if k.lower() != "set-cookie":
            continue
        parts = [p.strip() for p in v.split(";") if p.strip()]
        cname = (parts[0] if parts else v).split("=", 1)[0].strip()
        low_full = v.lower()
        has_secure = "secure" in low_full
        has_httponly = "httponly" in low_full
        samesite = next(
            (p.split("=", 1)[1].strip() if "=" in p else p for p in parts[1:] if p.lower().startswith("samesite")),
            "not_set",
        )
        max_age = next(
            (p.split("=", 1)[1].strip() for p in parts[1:] if p.lower().startswith("max-age=")),
            None,
        )
        expires = next(
            (p.split("=", 1)[1].strip() for p in parts[1:] if p.lower().startswith("expires=")),
            None,
        )
        lifetime = f"Max-Age={max_age}s" if max_age else (f"Expires={expires}" if expires else "Session")

        cookies.append({
            "name": cname,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite,
            "lifetime": lifetime,
        })

        if is_https and not has_secure:
            findings.append({
                "severity": "MEDIUM",
                "title": "Cookie Missing Secure Flag",
                "detail": f"Cookie '{cname}' ({lifetime}) lacks Secure over HTTPS.",
                "impact": "Cookie may be exposed over non-HTTPS sub-requests or downgrade paths.",
                "control": f"Add the 'Secure' attribute to cookie '{cname}'.",
            })
        if not has_httponly:
            findings.append({
                "severity": "LOW",
                "title": "Cookie Missing HttpOnly Flag",
                "detail": f"Cookie '{cname}' ({lifetime}) is accessible to client-side scripts.",
                "impact": "Client-side script injection could read cookie value if script execution occurs.",
                "control": f"Enable 'HttpOnly' on cookie '{cname}' unless script access is strictly required.",
            })
        if max_age and max_age.isdigit() and int(max_age) > 2592000:
            findings.append({
                "severity": "LOW",
                "title": "Long Cookie Lifetime",
                "detail": f"Cookie '{cname}' sets {lifetime} (>30 days).",
                "impact": "Extended persistence increases exposure window if a session or token is leaked.",
                "control": "Shorten cookie Max-Age/Expires and rotate session identifiers periodically.",
            })
    return cookies, findings


def analyze_cors_and_csp(headers_map: dict, raw_headers: list, is_https: bool) -> tuple:
    acao = headers_map.get("access-control-allow-origin")
    acac = headers_map.get("access-control-allow-credentials")
    acam = headers_map.get("access-control-allow-methods")
    csp_raw = headers_map.get("content-security-policy", "")

    directives = {}
    for chunk in csp_raw.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        tokens = chunk.split()
        directives[tokens[0].lower()] = tokens[1:]

    csp_urls = sorted(set(re.findall(r"(?:https?|wss?)://[^\s;'\"]+", csp_raw)))
    csp_domains = sorted({re.sub(r"/.*$", "", re.sub(r"^(?:https?|wss?)://", "", u)) for u in csp_urls})

    findings = []
    if acao == "*" and (acac or "").lower() == "true":
        findings.append({
            "severity": "HIGH",
            "title": "Overly Permissive CORS with Credentials",
            "detail": "Access-Control-Allow-Origin is '*' while Access-Control-Allow-Credentials is true.",
            "impact": "Cross-origin requests from untrusted origins could access authenticated responses.",
            "control": "Explicitly allowlist trusted origins and never pair wildcard '*' with credentials.",
        })
    elif acao == "*":
        findings.append({
            "severity": "LOW",
            "title": "Wildcard CORS Origin",
            "detail": "Access-Control-Allow-Origin is set to '*'.",
            "impact": "Any external origin can read public cross-origin responses.",
            "control": "Scope Access-Control-Allow-Origin to required origins if responses contain sensitive data.",
        })

    if csp_raw:
        if "unsafe-inline" in csp_raw.lower() or "unsafe-eval" in csp_raw.lower():
            findings.append({
                "severity": "MEDIUM",
                "title": "Weak CSP Script Directives",
                "detail": "CSP contains 'unsafe-inline' or 'unsafe-eval'.",
                "impact": "Weakens script origin restriction and increases XSS blast radius.",
                "control": "Remove unsafe-eval and migrate inline scripts/styles to strict nonces or hashes.",
            })
        if "default-src" not in directives and "script-src" not in directives:
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing CSP Fallback Directive",
                "detail": "CSP lacks both 'default-src' and 'script-src'.",
                "impact": "Resource types without explicit directives may fall back to permissive behavior.",
                "control": "Define a restrictive 'default-src' baseline and explicit resource directives.",
            })
        if "frame-ancestors" not in directives and "x-frame-options" not in headers_map:
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing Clickjacking Framing Controls",
                "detail": "Neither CSP 'frame-ancestors' nor 'X-Frame-Options' is present.",
                "impact": "Page may be embedded inside unauthorized frames.",
                "control": "Set 'frame-ancestors' in CSP and/or 'X-Frame-Options: DENY' or 'SAMEORIGIN'.",
            })

    cookies, cookie_findings = analyze_cookies_deep(raw_headers, is_https)
    findings.extend(cookie_findings)

    return {
        "cors": {
            "access_control_allow_origin": acao,
            "access_control_allow_credentials": acac,
            "access_control_allow_methods": acam,
        },
        "csp": {
            "present": bool(csp_raw),
            "directives_count": len(directives),
            "directives_keys": sorted(directives.keys()),
            "domains": csp_domains,
        },
        "cookies": cookies,
    }, findings


SOCIAL_DOMAINS = (
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "linkedin.com",
    "youtube.com",
    "t.me",
    "telegram.me",
    "github.com",
    "tiktok.com",
)


def extract_social_links(links: list) -> list:
    from urllib.parse import urlparse
    found = []
    seen = set()
    for l in links:
        host = (urlparse(l).hostname or "").lower()
        if any(host == sd or host.endswith("." + sd) for sd in SOCIAL_DOMAINS):
            if l not in seen:
                seen.add(l)
                found.append(l)
    return found[:25]


MULTI_SOCIAL_TEMPLATES = {
    "facebook": "https://www.facebook.com/{u}",
    "instagram": "https://www.instagram.com/{u}/",
    "x": "https://x.com/{u}",
    "twitter": "https://twitter.com/{u}",
    "tiktok": "https://www.tiktok.com/@{u}",
    "youtube": "https://www.youtube.com/@{u}",
    "linkedin": "https://www.linkedin.com/in/{u}",
    "github": "https://github.com/{u}",
    "telegram": "https://t.me/{u}",
    "reddit": "https://www.reddit.com/user/{u}/",
    "pinterest": "https://www.pinterest.com/{u}/",
    "medium": "https://medium.com/@{u}",
}


def extract_username_candidate(raw_input: str, final_url: str = "") -> str:
    from urllib.parse import urlparse
    import re
    for candidate in (final_url.strip(), raw_input.strip()):
        if not candidate:
            continue
        if candidate.startswith("@"):
            cleaned = re.sub(r"[^A-Za-z0-9._-]", "", candidate[1:])
            if len(cleaned) >= 2:
                return cleaned
        if "://" in candidate or "/" in candidate:
            parsed = urlparse(candidate if "://" in candidate else "https://" + candidate)
            parts = [seg for seg in (parsed.path or "").split("/") if seg]
            skip_segs = {"share", "p", "reel", "reels", "watch", "profile.php", "sharer.php", "in", "user", "u"}
            for seg in reversed(parts):
                seg_clean = seg.lstrip("@")
                if seg_clean.lower() not in skip_segs and re.match(r"^[A-Za-z0-9._-]{2,40}$", seg_clean) and not seg_clean.isdigit():
                    return seg_clean
        else:
            if "@" not in candidate and not re.match(r"^\+?\d{6,15}$", candidate.strip()):
                cleaned = re.sub(r"[^A-Za-z0-9._-]", "", candidate.strip().lstrip("@"))
                if len(cleaned) >= 2:
                    return cleaned
    return ""


def scan_social_platforms_for_username(username: str) -> list:
    from concurrent.futures import ThreadPoolExecutor
    import urllib.request
    import urllib.error
    if not username:
        return []

    def _probe_platform(item):
        plat, tmpl = item
        profile_url = tmpl.format(u=username)
        try:
            req = urllib.request.Request(
                profile_url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; coder4silnt-alpha/15.0)"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                code = getattr(resp, "status", 200)
                return {"platform": plat, "url": profile_url, "status": code, "reachable": code in (200, 301, 302)}
        except urllib.error.HTTPError as he:
            return {"platform": plat, "url": profile_url, "status": he.code, "reachable": he.code in (200, 301, 302, 403, 999)}
        except Exception:
            return {"platform": plat, "url": profile_url, "status": None, "reachable": False}

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(_probe_platform, MULTI_SOCIAL_TEMPLATES.items()))
    return [r for r in results if r.get("reachable")]


def classify_extracted_numbers(raw_matches: list) -> tuple:
    import re
    valid_phones = []
    numeric_ids = []
    seen_p = set()
    seen_i = set()

    for item in raw_matches:
        cleaned = item.strip()
        digits = re.sub(r"\D", "", cleaned)
        if not digits:
            continue
        is_intl = cleaned.startswith("+") or cleaned.startswith("00")
        has_phone_sep = any(ch in cleaned for ch in (" ", "-", "(", ")"))
        is_local_mobile = digits.startswith(("010", "011", "012", "015", "05", "07", "06")) and 10 <= len(digits) <= 12

        if (is_intl and 9 <= len(digits) <= 15) or is_local_mobile or (has_phone_sep and 10 <= len(digits) <= 14):
            if cleaned not in seen_p:
                seen_p.add(cleaned)
                valid_phones.append(cleaned)
        else:
            if cleaned not in seen_i:
                seen_i.add(cleaned)
                numeric_ids.append(cleaned)

    return valid_phones[:20], numeric_ids[:20]


def detect_waf_cdn_and_tech(headers: dict, body: str, ptr_records: list) -> dict:
    import re
    h_lower = {k.lower(): str(v) for k, v in (headers or {}).items()}
    b_lower = (body or "").lower()
    ptr_joined = " ".join(ptr_records or []).lower()

    waf_cdn = []
    if "cf-ray" in h_lower or "cloudflare" in h_lower.get("server", "").lower() or "cloudflare" in ptr_joined:
        waf_cdn.append("Cloudflare WAF/CDN")
    if "x-amz-cf-id" in h_lower or "cloudfront" in ptr_joined:
        waf_cdn.append("AWS CloudFront")
    if "akamai" in h_lower.get("server", "").lower() or "x-akamai-transformed" in h_lower or "akamaitechnologies" in ptr_joined:
        waf_cdn.append("Akamai CDN/WAF")
    if "x-served-by" in h_lower and "cache-" in h_lower.get("x-served-by", "").lower():
        waf_cdn.append("Fastly CDN")
    if "x-sucuri-id" in h_lower:
        waf_cdn.append("Sucuri WAF")
    if "x-iinfo" in h_lower or "incapsula" in h_lower.get("x-cdn", "").lower():
        waf_cdn.append("Imperva / Incapsula WAF")

    tech_stack = []
    for hdr_key in ("server", "x-powered-by", "x-generator", "x-aspnet-version"):
        if h_lower.get(hdr_key):
            tech_stack.append(f"{hdr_key}: {h_lower[hdr_key]}")

    signatures = {
        "WordPress": ("wp-content/", "wp-includes/"),
        "Laravel": ("laravel_session", "csrf-token"),
        "Next.js": ("_next/static", "__next_data__"),
        "React": ("react-root", "data-reactroot"),
        "Vue.js": ("data-v-", "__vue__"),
        "Shopify": ("cdn.shopify.com", "shopify.theme"),
        "Drupal": ("drupal-settings-json", "/sites/default/files"),
        "Joomla": ("/media/jui/", "joomla!"),
    }
    for tech_name, markers in signatures.items():
        if any(m in b_lower for m in markers):
            tech_stack.append(tech_name)

    api_endpoints = sorted(set(re.findall(r"""["']((?:/api/|/v[1-9]/|/graphql|/rest/)[^"'\s<>]{1,80})["']""", body or "")))[:20]

    return {
        "waf_cdn": waf_cdn or ["Direct Origin / No obvious CDN-WAF header"],
        "tech_stack": list(dict.fromkeys(tech_stack))[:15] or ["Not explicitly disclosed"],
        "api_endpoints": api_endpoints,
    }


def inspect_cookie_security(set_cookie_headers: list) -> dict:
    total = len(set_cookie_headers or [])
    missing_secure = 0
    missing_httponly = 0
    missing_samesite = 0
    for c in (set_cookie_headers or []):
        cl = c.lower()
        if "secure" not in cl:
            missing_secure += 1
        if "httponly" not in cl:
            missing_httponly += 1
        if "samesite" not in cl:
            missing_samesite += 1
    return {
        "total": total,
        "missing_secure": missing_secure,
        "missing_httponly": missing_httponly,
        "missing_samesite": missing_samesite,
    }


def analyze_url_osint(target: str) -> dict:
    url = normalize_url(target)
    host = extract_host(url)
    ipv4, ipv6, ptrs, errors = [], [], [], []

    try:
        for info in socket.getaddrinfo(host, None):
            fam, ip = info[0], info[4][0]
            if fam == socket.AF_INET and ip not in ipv4:
                ipv4.append(ip)
            elif fam == socket.AF_INET6 and ip not in ipv6:
                ipv6.append(ip)
        for ip in ipv4 + ipv6:
            try:
                rev = socket.gethostbyaddr(ip)[0]
                if rev not in ptrs:
                    ptrs.append(rev)
            except Exception:
                pass
    except Exception as exc:
        errors.append(f"DNS lookup error: {exc}")

    mx_records, mx_err = run_dig_query("MX", host, timeout_sec=10)
    txt_records, txt_err = run_dig_query("TXT", host, timeout_sec=10)
    if mx_err and not mx_records:
        errors.append(mx_err)
    if txt_err and not txt_records:
        errors.append(txt_err)

    open_ports = []
    for port in COMMON_PORTS:
        try:
            with socket.create_connection((host, port), timeout=2.0) as sock:
                banner = ""
                try:
                    sock.settimeout(0.8)
                    if port in (80, 8080):
                        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    data = sock.recv(128)
                    if data:
                        banner = data.decode("utf-8", errors="ignore").splitlines()[0].strip()
                except Exception:
                    banner = ""
                open_ports.append({"port": port, "banner": banner})
        except OSError:
            continue

    status = None
    final_url = url
    headers_map = {}
    raw_headers = []
    body = ""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; coder4silnt-alpha/14.0)", "Origin": "https://example.org"},
        )
        with urllib.request.urlopen(req, timeout=12.0) as resp:
            status = getattr(resp, "status", 200)
            final_url = resp.geturl() or url
            raw_headers = list(resp.headers.items())
            headers_map = {k.lower(): v for k, v in raw_headers}
            body = resp.read(300000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as he:
        status = he.code
        raw_headers = list(he.headers.items()) if he.headers else []
        headers_map = {k.lower(): v for k, v in raw_headers}
        errors.append(f"HTTP {he.code}: {he.reason}")
    except Exception as exc:
        errors.append(f"HTTP error: {exc}")

    parsed_final = urlparse(final_url)
    is_https = parsed_final.scheme == "https"
    policy_details, policy_findings = analyze_cors_and_csp(headers_map, raw_headers, is_https)

    root_domain = ".".join(host.split(".")[-2:]) if len(host.split(".")) >= 2 else host
    links = sorted(set(re.findall(r"https?://[^\s\"'<>()]+", body))) if body else []
    subdomains = sorted({
        (urlparse(l).hostname or "").lower()
        for l in links
        if (urlparse(l).hostname or "") and root_domain and (
            (urlparse(l).hostname or "").lower() == root_domain
            or (urlparse(l).hostname or "").lower().endswith("." + root_domain)
        )
    })
    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", body))) if body else []
    raw_num_matches = sorted(set(re.findall(r"\+?\d[\d\s().-]{7,}\d", body))) if body else []
    phones, numeric_ids = classify_extracted_numbers(raw_num_matches)

    public_paths = []
    for p in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.git/config", "/.env", "/api"):
        full = urljoin(final_url.rstrip("/") + "/", p.lstrip("/"))
        try:
            preq = urllib.request.Request(full, headers={"User-Agent": "coder4silnt-alpha/14.0"})
            with urllib.request.urlopen(preq, timeout=5.0) as pr:
                public_paths.append({"path": p, "status": getattr(pr, "status", 200)})
        except urllib.error.HTTPError as phe:
            public_paths.append({"path": p, "status": phe.code})
        except Exception:
            public_paths.append({"path": p, "status": None})

    return {
        "target_url": url,
        "final_url": final_url,
        "http_status": status,
        "host": host,
        "ips": ipv4 + ipv6,
        "ipv4": ipv4,
        "ipv6": ipv6,
        "ptr": ptrs,
        "mx_records": mx_records,
        "txt_records": txt_records[:15],
        "open_ports": open_ports,
        "headers_present": sorted(k for k in SECURITY_HEADERS if k in headers_map),
        "headers_missing": [k for k in SECURITY_HEADERS if k not in headers_map],
        "headers_map": headers_map,
        "cors": policy_details["cors"],
        "csp": policy_details["csp"],
        "cookies": policy_details["cookies"],
        "policy_findings": policy_findings,
        "csp_domains": policy_details["csp"]["domains"],
        "subdomains": subdomains,
        "social_links": extract_social_links(links),
        "detected_username": extract_username_candidate(target, final_url),
        "matched_social_profiles": scan_social_platforms_for_username(extract_username_candidate(target, final_url)),
        "emails_found": emails[:25],
        "phones_found": phones,
        "numeric_ids_found": numeric_ids,
        "public_paths": public_paths,
        "errors": errors,
    }


def analyze_phone_osint(phone: str) -> dict:
    raw = phone.strip()
    digits = re.sub(r"[^\d+]", "", raw)
    normalized = digits if digits.startswith("+") else ("+" + digits.lstrip("0")) if digits else ""
    matched_region = "Unknown / Needs international prefix"
    matched_code = None
    for code in sorted(COUNTRY_PREFIXES.keys(), key=len, reverse=True):
        if normalized.startswith(code):
            matched_code = code
            matched_region = COUNTRY_PREFIXES[code]
            break
    numbering_hint = "General E.164 international numbering plan"
    for pfx in sorted(EGYPT_PREFIX_HINTS.keys(), key=len, reverse=True):
        if normalized.startswith(pfx):
            numbering_hint = EGYPT_PREFIX_HINTS[pfx]
            break
    digit_only = re.sub(r"\D", "", normalized)
    valid_length = 7 <= len(digit_only) <= 15
    findings = []
    if not valid_length:
        findings.append({
            "severity": "LOW",
            "title": "Non-Standard Phone Format",
            "detail": "Number length falls outside standard E.164 range.",
            "impact": "May cause parsing or validation mismatches in communication systems.",
            "control": "Normalize phone numbers to international E.164 format and validate length.",
        })
    return {
        "input": raw,
        "normalized": normalized,
        "digit_count": len(digit_only),
        "valid_e164_range": valid_length,
        "country_code": matched_code,
        "region_guess": matched_region,
        "numbering_hint": numbering_hint,
        "external_leak_lookup": "Not queried (live device geolocation and private carrier records are excluded)",
        "findings": findings,
    }


def analyze_email_osint(email_addr: str) -> dict:
    addr = email_addr.strip().lower()
    errors = []
    findings = []
    valid_syntax = bool(re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", addr))
    local_part, _, domain = addr.partition("@")
    ips = []
    mx_hosts = []
    txt_records = []
    dmarc_records = []

    if domain:
        try:
            for info in socket.getaddrinfo(domain, None):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except Exception as exc:
            errors.append(f"Domain A/AAAA lookup error: {exc}")

        mx_hosts, mx_err = run_dig_query("MX", domain, timeout_sec=12)
        txt_records, txt_err = run_dig_query("TXT", domain, timeout_sec=12)
        dmarc_records, dm_err = run_dig_query("TXT", f"_dmarc.{domain}", timeout_sec=12)
        if mx_err and not mx_hosts:
            errors.append(mx_err)
        if txt_err and not txt_records:
            errors.append(txt_err)
        if dm_err and not dmarc_records:
            errors.append(dm_err)

    has_spf = any("v=spf1" in t.lower() for t in txt_records)
    has_dmarc = any("v=dmarc1" in t.lower() for t in dmarc_records)

    if valid_syntax and domain and not has_spf:
        findings.append({
            "severity": "MEDIUM",
            "title": "Missing SPF Policy",
            "detail": f"No SPF record found for {domain}.",
            "impact": "Receiving mail servers lack explicit sender authorization rules for the domain.",
            "control": f"Publish a valid SPF TXT record for {domain} listing authorized mail senders.",
        })
    if valid_syntax and domain and not has_dmarc:
        findings.append({
            "severity": "MEDIUM",
            "title": "Missing DMARC Policy",
            "detail": f"No DMARC record found for _dmarc.{domain}.",
            "impact": "Domain lacks standardized reporting and quarantine/reject handling policy.",
            "control": f"Publish a DMARC policy record under _dmarc.{domain} and monitor alignment reports.",
        })

    mx_joined = " ".join(mx_hosts).lower()
    if "google.com" in mx_joined or "googlemail.com" in mx_joined:
        mail_provider = "Google / Gmail / Google Workspace"
    elif "outlook.com" in mx_joined or "protection.outlook.com" in mx_joined:
        mail_provider = "Microsoft 365 / Exchange Online"
    elif "zoho." in mx_joined:
        mail_provider = "Zoho Mail"
    elif "protonmail." in mx_joined or "proton.ch" in mx_joined:
        mail_provider = "Proton Mail"
    elif mx_hosts:
        mail_provider = f"Custom / Other ({mx_hosts[0]})"
    else:
        mail_provider = "Unknown / No MX resolved"

    mta_sts_recs, _ = run_dig_query("TXT", f"_mta-sts.{domain}", timeout_sec=5) if domain else ([], None)
    has_mta_sts = any("v=stsv1" in t.lower() for t in mta_sts_recs)

    return {
        "email": addr,
        "valid_syntax": valid_syntax,
        "local_part": local_part,
        "domain": domain,
        "mail_provider": mail_provider,
        "domain_ips": ips,
        "mx_records": mx_hosts,
        "txt_records": txt_records[:15],
        "spf_present": has_spf,
        "dmarc_present": has_dmarc,
        "mta_sts_present": has_mta_sts,
        "external_leak_lookup": "Public DNS & mail policy only (device/session info is restricted to account owner)",
        "findings": findings,
        "errors": errors,
    }


def assess_vulnerabilities(url_data: dict, host: str) -> list:
    vulns = []
    hmap = url_data.get("headers_map", {})
    parsed = urlparse(url_data.get("final_url") or url_data.get("target_url") or "")

    if parsed.scheme != "https":
        vulns.append({
            "severity": "HIGH",
            "title": "Cleartext Transport (HTTP)",
            "detail": "Target does not enforce HTTPS.",
            "impact": "Traffic in transit can be intercepted or altered on untrusted networks.",
            "control": "Enforce HTTPS with TLS 1.2+ and redirect all HTTP traffic to HTTPS.",
        })

    for hdr, (desc, sev) in SECURITY_HEADERS.items():
        if hdr not in hmap:
            vulns.append({
                "severity": sev,
                "title": "Missing Security Header",
                "detail": desc,
                "impact": f"Reduces browser-side defense posture due to {desc.lower()}.",
                "control": f"Configure '{hdr}' header at the web server or edge reverse proxy.",
            })

    for leak_k in ("server", "x-powered-by", "x-aspnet-version"):
        if leak_k in hmap and hmap[leak_k].strip():
            vulns.append({
                "severity": "LOW",
                "title": "Server Banner Disclosure",
                "detail": f"{leak_k}: {hmap[leak_k].strip()}",
                "impact": "Reveals software stack details that aid fingerprinted reconnaissance.",
                "control": f"Suppress or minimize '{leak_k}' response header information.",
            })

    for pinfo in url_data.get("public_paths", []):
        if pinfo.get("path") in ("/.git/config", "/.env") and pinfo.get("status") == 200:
            vulns.append({
                "severity": "HIGH",
                "title": "Exposed Sensitive File",
                "detail": f"{pinfo['path']} returned HTTP 200.",
                "impact": "Repository metadata or environment secrets could be exposed publicly.",
                "control": f"Block external access to {pinfo['path']} and rotate any exposed secrets.",
            })

    vulns.extend(url_data.get("policy_findings", []))

    if parsed.scheme == "https" and host:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    proto = ssock.version() or ""
                    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        vulns.append({
                            "severity": "HIGH",
                            "title": "Weak TLS Protocol",
                            "detail": f"Negotiated {proto}",
                            "impact": "Deprecated cryptographic protocols are vulnerable to known downgrade/cipher weaknesses.",
                            "control": "Disable legacy TLS/SSL versions and require TLS 1.2 or TLS 1.3.",
                        })
        except Exception as exc:
            vulns.append({
                "severity": "MEDIUM",
                "title": "TLS Handshake Issue",
                "detail": str(exc),
                "impact": "Clients may fail TLS verification or encounter connection instability.",
                "control": "Verify certificate chain, hostname alignment, and TLS listener configuration.",
            })

    return vulns


def build_defense_matrix(vulns: list) -> list:
    by_sev = {"HIGH": [], "MEDIUM": [], "LOW": []}
    for item in vulns:
        sev = item.get("severity", "LOW")
        by_sev.setdefault(sev, []).append(item.get("title", "Finding"))

    defaults = {
        "HIGH": "Enforce HTTPS/TLS 1.2+, strict CSP/HSTS, restrict exposed sensitive assets, and apply immediate patching.",
        "MEDIUM": "Harden cookie flags/lifetimes, tighten CORS and CSP directives, and strengthen session/auth controls.",
        "LOW": "Suppress verbose server banners, enforce baseline security headers, and maintain continuous monitoring and logging.",
    }
    return [
        {"severity": sev, "count": len(by_sev.get(sev, [])), "defense_control": defaults[sev]}
        for sev in ("HIGH", "MEDIUM", "LOW")
    ]


import time

def build_unified_report(
    mode_label: str,
    query_label: str = "",
    url_target: str = "",
    phone_target: str = "",
    email_target: str = "",
    with_nmap: bool = False,
) -> dict:
    scan_started_ts = time.perf_counter()
    tools_inv = inspect_system_tools()

    effective_url = url_target.strip()
    effective_email = email_target.strip()
    effective_phone = phone_target.strip()

    if not effective_url and effective_email and "@" in effective_email:
        dom = effective_email.split("@", 1)[1].strip()
        if dom:
            effective_url = f"https://{dom}"

    url_info = analyze_url_osint(effective_url) if effective_url else None
    if not effective_email and url_info and url_info.get("emails_found"):
        effective_email = url_info["emails_found"][0]
    if not effective_phone and url_info and url_info.get("phones_found"):
        effective_phone = url_info["phones_found"][0]

    phone_info = analyze_phone_osint(effective_phone) if effective_phone else None
    email_info = analyze_email_osint(effective_email) if effective_email else None

    dns_host = (
        url_info.get("host", "")
        if url_info
        else (email_info.get("domain", "") if email_info else "")
    )
    nmap_summary = run_optional_nmap_summary(dns_host, with_nmap)

    vulns = []
    if url_info:
        vulns.extend(assess_vulnerabilities(url_info, url_info.get("host", "")))
    if phone_info:
        vulns.extend(phone_info.get("findings", []))
    if email_info:
        vulns.extend(email_info.get("findings", []))

    sev_counts = {
        "HIGH": sum(1 for v in vulns if v["severity"] == "HIGH"),
        "MEDIUM": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
        "LOW": sum(1 for v in vulns if v["severity"] == "LOW"),
    }

    errors = []
    if url_info:
        errors.extend(url_info.get("errors", []))
    if email_info:
        errors.extend(email_info.get("errors", []))

    ips = list(dict.fromkeys(
        (url_info.get("ips", []) if url_info else []) + (email_info.get("domain_ips", []) if email_info else [])
    ))
    host_label = dns_host or (phone_info.get("normalized", "") if phone_info else "")
    open_ports = [p["port"] for p in url_info.get("open_ports", [])] if url_info else []
    csp_domains = url_info.get("csp_domains", []) if url_info else []
    subdomains = url_info.get("subdomains", []) if url_info else []
    cookies_count = len(url_info.get("cookies", [])) if url_info else 0
    all_hosts = sorted(set(([host_label] if host_label else []) + csp_domains + subdomains))

    scope_boundaries = {
        "depth_note": "Checks cover configuration, headers, cookies, TLS, CORS/CSP, and common paths; deep app logic, DB, authz/RBAC, or advanced path testing require specialized authorized assessment.",
        "external_tools_note": "System CLI tool inventory is collected automatically; optional nmap summary runs only when explicitly requested on an authorized target.",
        "identity_lookup_note": "Email and phone checks cover structural formatting and DNS/MX/SPF/DMARC; external breach databases or third-party APIs require an authorized connected source.",
    }

    elapsed_sec = round(time.perf_counter() - locals().get('scan_started_ts', time.perf_counter()), 2)
    return {
        "meta": {
            "duration_seconds": elapsed_sec,
            "team_tier": "ALPHA_TEAM",
            "tool": "coder4silnt",
            "query": query_label or mode_label,
            "mode": mode_label,
            "timestamp_epoch": int(time.time()),
        },
        "system_tools": tools_inv,
        "nmap_summary": nmap_summary,
        "url_osint": url_info,
        "email_osint": email_info,
        "phone_osint": phone_info,
        "scope_boundaries": scope_boundaries,
        "defense_matrix": build_defense_matrix(vulns),
        "vulnerabilities": {
            "total": len(vulns),
            "by_severity": sev_counts,
            "items": vulns,
        },
        "summary_counts": {
            "installed_tools_count": tools_inv["installed_count"],
            "open_ports_count": len(open_ports),
            "open_ports": open_ports,
            "vulnerabilities_count": len(vulns),
            "high_count": sev_counts["HIGH"],
            "medium_count": sev_counts["MEDIUM"],
            "low_count": sev_counts["LOW"],
            "ips_count": len(ips),
            "ips": ips,
            "hosts_count": len(all_hosts),
            "cookies_count": cookies_count,
            "social_links_count": len(url_info.get("social_links", [])) if url_info else 0,
            "emails_found_count": len(url_info.get("emails_found", [])) if url_info else 0,
            "phones_found_count": len(url_info.get("phones_found", [])) if url_info else 0,
            "csp_domains_count": len(csp_domains),
            "subdomains_count": len(subdomains),
            "errors_count": len(errors),
            "errors": errors,
        },
    }


def format_unified_report(rep: dict) -> str:
    m = rep["meta"]
    ti = rep["system_tools"]
    nm = rep["nmap_summary"]
    u = rep.get("url_osint")
    e = rep.get("email_osint")
    p = rep.get("phone_osint")
    sb = rep["scope_boundaries"]
    v = rep["vulnerabilities"]
    sc = rep["summary_counts"]

    lines = [
        ALPHA_BANNER.strip("\n"),
        "                                 CODER4SILNT",
        "=" * 74,
        f"UNIFIED ALPHA TEAM REPORT | QUERY: {m['query']} | MODE: {m['mode']}",
        "=" * 74,
        f"[01] SYSTEM CLI TOOLS ({ti['installed_count']}/{ti['total_checked']} AVAILABLE)",
    ]
    for item in ti["tools"]:
        state = f"YES ({item['path']})" if item["installed"] else "NO"
        lines.append(f"  - {item['tool']:10s} : {state:28s} | {item['info']}")

    lines.extend([
        "",
        f"[02] OPTIONAL NMAP SUMMARY | STATUS: {nm['status']}",
    ])
    if nm.get("services"):
        for svc in nm["services"]:
            lines.append(f"  - {svc['port_proto']:10s} | {svc['service']} | {svc['version']}")
    else:
        lines.append("  - No open service details recorded.")
    lines.append("")

    if u:
        cors = u.get("cors", {})
        csp = u.get("csp", {})
        lines.extend([
            "[03] TARGET URL & SURFACE INTELLIGENCE",
            f"  Target URL   : {u['target_url']} -> Final: {u['final_url']} (HTTP {u['http_status']})",
            f"  DNS Host     : {u['host']}",
            f"  IP Addresses : {', '.join(u['ips']) or 'None'}",
            f"  PTR Records  : {', '.join(u['ptr']) or 'None'}",
            f"  MX Records   : {', '.join(u['mx_records']) or 'None'}",
            f"  Open Ports   : {', '.join(str(x['port']) for x in u['open_ports']) or 'None'}",
            f"  CORS         : ACAO={cors.get('access_control_allow_origin')} | ACAC={cors.get('access_control_allow_credentials')} | Methods={cors.get('access_control_allow_methods')}",
            f"  CSP          : present={csp.get('present')} | directives={len(csp.get('directives_keys', []))} | domains={len(u['csp_domains'])}",
            f"  Cookies      : {len(u['cookies'])}",
            f"  Subdomains   : {', '.join(u['subdomains']) or 'None'}",
            f"  Username      : {u.get('detected_username') or 'None'}" ,
            f"  Social URLs   : { ', '.join([x['url'] for x in (u.get('matched_social_profiles') or [])][:6]) or 'None' }",
            f"  Social Links : {', '.join(u.get('social_links', [])) or 'None'}",
            f"  Emails Found : {', '.join(u['emails_found']) or 'None'}",
            f"  Phones Found : {', '.join(u['phones_found']) or 'None'}",
            f"  Numeric IDs  : {', '.join(u.get('numeric_ids_found', [])[:8]) or 'None'}",
        ])
        for c in u.get("cookies", []):
            lines.append(f"    * Cookie [{c['name']}]: Secure={c['secure']} | HttpOnly={c['httponly']} | SameSite={c['samesite']} | {c['lifetime']}")
        lines.append("")

    if e:
        lines.extend([
            "[04] EMAIL INTELLIGENCE",
            f"  Email        : {e['email']}",
            f"  Valid Syntax : {e['valid_syntax']}",
            f"  Domain       : {e['domain'] or 'N/A'}",
            f"  Mail Provider: {e.get('mail_provider', 'N/A')}",
            f"  Domain IPs   : {', '.join(e['domain_ips']) or 'None'}",
            f"  MX Records   : {', '.join(e['mx_records']) or 'None'}",
            f"  Mail Security: SPF={e['spf_present']} | DMARC={e['dmarc_present']} | MTA-STS={e.get('mta_sts_present', False)}",
            f"  External DB  : {e['external_leak_lookup']}",
            "",
        ])

    if p:
        lines.extend([
            "[05] PHONE NUMBER INTELLIGENCE",
            f"  Input        : {p['input']}",
            f"  Normalized   : {p['normalized'] or 'N/A'}",
            f"  Digit Count  : {p['digit_count']} (E.164 range valid: {p['valid_e164_range']})",
            f"  Country Code : {p['country_code'] or 'N/A'} | Region: {p['region_guess']}",
            f"  Plan Hint    : {p.get('numbering_hint', 'N/A')}",
            f"  External DB  : {p['external_leak_lookup']}",
            "",
        ])


    fp = (u or {}).get("intel_fingerprint") or {}
    ca = (u or {}).get("cookie_audit") or {}
    pub_map = {x.get("path"): x.get("status") for x in ((u or {}).get("public_paths") or [])}
    dur_s = rep.get("meta", {}).get("duration_seconds", "N/A")

    lines.extend([
        "",
        "-" * 74,
        "[06B] ASN & NETWORK POSTURE / WAF-CDN DETECTION",
        "-" * 74,
        f"  - IP Addresses    : {', '.join(sc.get('ips') or []) or 'None'}",
        f"  - PTR / Reverse   : {', '.join((u or {}).get('ptr_records') or []) or 'None'}",
        f"  - Edge / WAF-CDN  : {', '.join(fp.get('waf_cdn') or ['N/A'])}",
        "",
        "-" * 74,
        "[06C] TECHNOLOGY & SERVER FINGERPRINT / API SURFACE",
        "-" * 74,
        f"  - Tech & Banners  : {', '.join(fp.get('tech_stack') or ['N/A'])}",
        f"  - API Endpoints   : {', '.join(fp.get('api_endpoints') or []) or 'None'}",
        "",
        "-" * 74,
        "[06D] SECURITY POLICIES, COOKIE AUDIT & SCAN TELEMETRY",
        "-" * 74,
        f"  - robots.txt      : HTTP {pub_map.get('/robots.txt', 'N/A')} | security.txt: HTTP {pub_map.get('/.well-known/security.txt', 'N/A')}",
        f"  - Cookie Flags    : Total={ca.get('total', sc.get('cookies_count', 0))} | No-Secure={ca.get('missing_secure', 0)} | No-HttpOnly={ca.get('missing_httponly', 0)} | No-SameSite={ca.get('missing_samesite', 0)}",
        f"  - Scan Duration   : {dur_s} seconds",
    ])

    lines.extend([
        "[06] ASSESSMENT SCOPE & BOUNDARIES",
        f"  - Depth & Logic : {sb['depth_note']}",
        f"  - CLI Tools     : {sb['external_tools_note']}",
        f"  - Identity OSINT: {sb['identity_lookup_note']}",
        "",
        "[07] FINDINGS & SEVERITY BREAKDOWN",
        f"  Total Findings : {v['total']} (HIGH: {v['by_severity']['HIGH']}, MEDIUM: {v['by_severity']['MEDIUM']}, LOW: {v['by_severity']['LOW']})",
    ])
    if v["items"]:
        for idx, item in enumerate(v["items"], 1):
            lines.append(f"    {idx}. [{item['severity']}] {item['title']} - {item['detail']}")
    else:
        lines.append("    No configuration issues detected by active checks.")

    lines.extend([
        "",
        "[08] REMEDIATION FLOW (RISK -> IMPACT -> CONTROL)",
    ])
    if v["items"]:
        for idx, item in enumerate(v["items"], 1):
            lines.append(f"    {idx}. [{item['severity']}] {item['title']}")
            lines.append(f"       Risk    : {item['detail']}")
            lines.append(f"       Impact  : {item.get('impact', 'Requires assessment.')}")
            lines.append(f"       Control : {item.get('control', 'Apply standard hardening.')}")
    else:
        lines.append("    No remediation actions required from active checks.")

    lines.extend([
        "",
        "[09] ERRORS",
        f"  Total Errors   : {sc['errors_count']}",
    ])
    if sc["errors"]:
        for err in sc["errors"]:
            lines.append(f"    - {err}")
    else:
        lines.append("    None")

    lines.extend([
        "",
        "-" * 74,
        "[10] FINAL COUNTERS (ORDERED SUMMARY)",
        "-" * 74,
        f"  1. Installed CLI Tools : {sc['installed_tools_count']}/{ti['total_checked']}",
        f"  2. Open Ports          : {sc['open_ports_count']} ({', '.join(map(str, sc['open_ports'])) or 'None'})",
        f"  3. Vulnerabilities     : {sc['vulnerabilities_count']} [HIGH={sc['high_count']}, MEDIUM={sc['medium_count']}, LOW={sc['low_count']}]",
        f"  4. IP Addresses        : {sc['ips_count']} ({', '.join(sc['ips']) or 'None'})",
        f"  5. Hosts / Domains     : {sc['hosts_count']}",
        f"  6. Cookies             : {sc['cookies_count']}",
        f"  7. CSP Domains         : {sc['csp_domains_count']}",
        f"  8. Subdomains          : {sc['subdomains_count']}",
        f"  9. Errors              : {sc['errors_count']}",
        "",
        "-" * 74,
        "[11] RISK-ALIGNED DEFENSE MATRIX (HIGH / MEDIUM / LOW)",
        "-" * 74,
    ])
    for dm in rep.get("defense_matrix", []):
        lines.append(f"  [{dm['severity']}] ({dm['count']} items) -> {dm['defense_control']}")
    lines.extend([
        "",
        "-" * 74,
        "[12] FINAL SUMMARY TABLE",
        "-" * 74,
        f"  | {'Metric':24s} | {'Value':43s} |",
        f"  | {'-' * 24} | {'-' * 43} |",
        f"  | {'Vulnerabilities':24s} | {f'{sc['vulnerabilities_count']} (H:{sc['high_count']} M:{sc['medium_count']} L:{sc['low_count']})':43s} |",
        f"  | {'Cookies':24s} | {str(sc['cookies_count']):43s} |",
        f"  | {'Emails Found':24s} | {str(sc.get('emails_found_count', 0)):43s} |",
        f"  | {'Phones Found':24s} | {str(sc.get('phones_found_count', 0)):43s} |",
        f"  | {'Social Links':24s} | {str(sc.get('social_links_count', 0)):43s} |",
        f"  | {'Matched Social':24s} | {str(len((u.get('matched_social_profiles') or []) if u else [])):43s} |",
        f"  | {'Open Ports':24s} | {( ', '.join(map(str, sc['open_ports'])) or 'None' )[:43]:43s} |",
        f"  | {'IP Addresses':24s} | {( ', '.join(sc['ips']) or 'None' )[:43]:43s} |",
        f"  | {'Subdomains':24s} | {str(sc['subdomains_count']):43s} |",
        f"  | {'Errors':24s} | {str(sc['errors_count']):43s} |",
        "=" * 74,
    ])
    return "\n".join(lines)


def colorize_terminal_report(plain_text: str) -> str:
    colored = []
    for ln in plain_text.splitlines():
        if ln.startswith("=" * 10) or ln.startswith("-" * 10):
            colored.append(f"{BLUE}{ln}{RESET}")
        elif ln.startswith("UNIFIED ALPHA TEAM REPORT") or ln.startswith("[10] FINAL COUNTERS") or ln.startswith("[11] RISK-ALIGNED DEFENSE MATRIX"):
            colored.append(f"{BOLD}{GOLD}{ln}{RESET}")
        elif re.match(r"^\[\d+\]\s+[A-Z0-9 /()&-]+$", ln.strip()):
            colored.append(f"{BOLD}{CYAN}{ln}{RESET}")
        elif "[HIGH]" in ln:
            colored.append(f"{BOLD}{RED}{ln}{RESET}")
        elif "[MEDIUM]" in ln:
            colored.append(f"{GOLD}{ln}{RESET}")
        elif "[LOW]" in ln:
            colored.append(f"{GREEN}{ln}{RESET}")
        else:
            colored.append(ln)
    return "\n".join(colored)


def save_single_txt_report(plain_text: str, report_label: str = "alpha_scan_target", append_mode: bool = False) -> dict:
    FINANCE_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = sanitize_query_name(report_label)
    sys_txt = FINANCE_DIR / f"{safe_name}.txt"

    if append_mode and sys_txt.exists():
        existing = sys_txt.read_text(encoding="utf-8", errors="ignore")
        sep = "\n\n" + ("#" * 74) + "\nNEXT BATCH TARGET SECTION\n" + ("#" * 74) + "\n\n"
        sys_txt.write_text(existing + sep + plain_text, encoding="utf-8")
    else:
        sys_txt.write_text(plain_text, encoding="utf-8")

    phone_txt_path = None
    for pdir in PHONE_DOWNLOAD_DIRS:
        try:
            pdir.mkdir(parents=True, exist_ok=True)
            dest = pdir / f"{safe_name}.txt"
            shutil.copy2(sys_txt, dest)
            phone_txt_path = str(dest)
            break
        except Exception:
            continue

    return {
        "query_name": safe_name,
        "system_txt": str(sys_txt),
        "phone_txt": phone_txt_path,
    }


def print_coder4silnt_menu() -> None:
    e = chr(27)
    b, bl, c, w, g, rd, r = e + "[1m", e + "[94m", e + "[96m", e + "[97m", e + "[93m", e + "[91m", e + "[0m"
    W = 48
    def row(txt, col):
        pad = max(0, W - len(txt))
        return bl + "|" + r + col + txt + (" " * pad) + r + bl + "|" + r
    print(b + c + "+" + ("-" * W) + "+" + r)
    print(row(" [1] OSINT URL & Social Scan", b + w))
    print(row(" [2] Phone Number Audit", b + w))
    print(row(" [3] Email Audit", b + w))
    print(row(" [4] Full Comprehensive Scan", b + bl))
    print(row(" [5] Deep Posture & APK Audit", b + g))
    print(row(" [6] Local Wi-Fi / Hotspot Audit", b + c))
    print(row(" [0] Exit", b + rd))
    print(b + c + "+" + ("-" * W) + "+" + r)


def interactive_menu(with_nmap_default: bool = False) -> None:
    os.system("clear")
    w = min(74, get_term_width())
    print(f"{BLUE}|{'-' * (w - 2)}|{RESET}")
    print(f"{BLUE}+{'-' * (w - 2)}+{RESET}")
    print_alpha_header()
    print_coder4silnt_menu()

    choice = input(f"\n{BOLD}{GOLD}Select option [0-6]: {RESET}").strip()
    if choice == "0":
        return

    url_in = ""
    phone_in = ""
    email_in = ""
    mode = "ALPHA_FULL_SCAN"

    if choice == "1":
        mode = "ALPHA_OSINT_URL"
        url_in = input(f"{CYAN}Enter target URL or domain: {RESET}").strip()
    elif choice == "2":
        mode = "ALPHA_PHONE_NUMBER"
        phone_in = input(f"{CYAN}Enter phone number (e.g. +201000000000): {RESET}").strip()
    elif choice == "3":
        mode = "ALPHA_EMAIL_OSINT"
        email_in = input(f"{CYAN}Enter email address: {RESET}").strip()
    elif choice == "4":
        mode = "ALPHA_FULL_COMPREHENSIVE_SCAN"
        url_in = input(f"{CYAN}Enter URL/domain (or press Enter to skip): {RESET}").strip()
        phone_in = input(f"{CYAN}Enter Phone number (or press Enter to skip): {RESET}").strip()
        email_in = input(f"{CYAN}Enter Email address (or press Enter to skip): {RESET}").strip()
    else:
        print(f"{RED}Invalid selection.{RESET}")
        return

    use_nmap = with_nmap_default
    if not use_nmap and shutil.which("nmap") and (url_in or email_in):
        ans = input(f"{CYAN}Include optional authorized nmap port/service summary? [y/N]: {RESET}").strip().lower()
        use_nmap = ans in ("y", "yes")

    query_label = url_in or email_in or phone_in or mode
    rep = build_unified_report(
        mode,
        query_label=query_label,
        url_target=url_in,
        phone_target=phone_in,
        email_target=email_in,
        with_nmap=use_nmap,
    )
    plain_text = format_unified_report(rep)
    raw_json = json.dumps(rep, indent=2, ensure_ascii=False)
    saved = save_single_txt_report(plain_text, report_label=query_label, append_mode=False)

    print("\n" + colorize_terminal_report(plain_text))
    print(f"\n{BLUE}+{'-' * (w - 2)}+{RESET}")
    print(f"{BOLD}{GREEN}SAVED UNIFIED REPORT BUNDLE{RESET}")
    print(f"  - System Report (TXT)  : {saved['system_txt']}")
    print(f"  - System Report (JSON) : {saved.get('system_txt', '')}")
    if saved["phone_txt"]:
        print(f"  - Phone Manager (TXT)  : {saved['phone_txt']}")
    else:
        print(f"  - Phone Manager (TXT)  : {GOLD}Not available (run 'termux-setup-storage' if needed).{RESET}")
    print(f"{BLUE}+{'-' * (w - 2)}+{RESET}")


def classify_batch_target(raw_target: str) -> tuple:
    val = raw_target.strip()
    if re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", val):
        return "ALPHA_BATCH_EMAIL", "", "", val
    digits_only = re.sub(r"[^\d+]", "", val)
    if re.match(r"^\+?\d{7,15}$", digits_only):
        return "ALPHA_BATCH_PHONE", "", val, ""
    return "ALPHA_BATCH_URL", val, "", ""


def run_batch_scan(batch_file: str, with_nmap: bool = False) -> None:
    fpath = Path(batch_file).expanduser()
    if not fpath.is_file():
        print(f"{RED}Batch file not found: {fpath}{RESET}")
        return
    targets = [
        ln.strip()
        for ln in fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    if not targets:
        print(f"{GOLD}No valid targets found in {fpath}.{RESET}")
        return

    bundle_label = f"batch_{fpath.stem}"
    print(f"\n{BOLD}{GOLD}BATCH SCAN STARTED | TARGETS: {len(targets)} | SINGLE REPORT: {sanitize_query_name(bundle_label)}.txt{RESET}")
    saved = None
    for idx, item in enumerate(targets, 1):
        mode, u_in, p_in, e_in = classify_batch_target(item)
        print(f"  {BOLD}{CYAN}[{idx}/{len(targets)}] Scanning: {item}{RESET}")
        rep = build_unified_report(
            mode, query_label=item, url_target=u_in, phone_target=p_in, email_target=e_in, with_nmap=with_nmap
        )
        plain_text = format_unified_report(rep)
        saved = save_single_txt_report(plain_text, report_label=bundle_label, append_mode=(idx > 1))
        sc = rep["summary_counts"]
        print(f"    {GREEN}Appended{RESET} -> Vulns: {sc['vulnerabilities_count']} | Errors: {sc['errors_count']}")

    if saved:
        print(f"\n{BOLD}{GREEN}SINGLE CONSOLIDATED REPORT SAVED{RESET}")
        print(f"  - System TXT : {saved['system_txt']}")
        if saved.get("phone_txt"):
            print(f"  - Phone TXT  : {saved['phone_txt']}")


def audit_apk_static(apk_path_str: str) -> dict:
    import zipfile
    import subprocess
    import shutil

    apk_path = Path(apk_path_str).expanduser()
    findings = []
    meta = {
        "apk_path": str(apk_path),
        "exists": apk_path.is_file(),
        "size_bytes": apk_path.stat().st_size if apk_path.is_file() else 0,
        "package_info": "N/A",
        "permissions_sample": [],
        "activities": [],
        "services": [],
    }

    if not apk_path.is_file():
        findings.append({
            "severity": "LOW",
            "title": "APK File Not Found on Local Path",
            "risk": f"Target APK path '{apk_path}' was not found locally.",
            "impact": "Static APK manifest and archive inspection could not be executed.",
            "control": "Verify the exact file path to the target APK and re-run the static audit.",
        })
        return {"meta": meta, "findings": findings}

    aapt_bin = shutil.which("aapt") or shutil.which("aapt2")
    if aapt_bin:
        try:
            proc = subprocess.run([aapt_bin, "dump", "badging", str(apk_path)], capture_output=True, text=True, timeout=8)
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            pkg_m = re.search(r"package:\s*name='([^']+)'", out)
            if pkg_m:
                meta["package_info"] = pkg_m.group(1)
            perms = re.findall(r"uses-permission:\s*name='([^']+)'", out)
            meta["permissions_sample"] = perms[:20]

            acts = re.findall(r"(?:launchable-activity|activity):\s*name='([^']+)'", out)
            svcs = re.findall(r"service:\s*name='([^']+)'", out)
            meta["activities"] = list(dict.fromkeys(acts))[:20]
            meta["services"] = list(dict.fromkeys(svcs))[:20]

            if any(x in perms for x in ("android.permission.INSTALL_PACKAGES", "android.permission.REQUEST_INSTALL_PACKAGES")):
                findings.append({
                    "severity": "HIGH",
                    "title": "Sensitive Package Install Permission Declared",
                    "risk": "APK declares package installation permission in manifest.",
                    "impact": "Elevated capability risk if abused or paired with untrusted sources.",
                    "control": "Review whether package installation permission is strictly required for core functionality.",
                })
            if any(x in perms for x in ("android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS")):
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Privacy-Sensitive Device Permissions Requested",
                    "risk": "APK requests access to SMS or Contacts data.",
                    "impact": "Higher privacy exposure if data handling or storage is insufficiently protected.",
                    "control": "Minimize requested permissions and enforce least-privilege access.",
                })
        except Exception:
            pass

    try:
        with zipfile.ZipFile(str(apk_path), "r") as zf:
            names = zf.namelist()
            meta["entries_count"] = len(names)
            raw_manifest = b""
            if "AndroidManifest.xml" in names:
                try:
                    raw_manifest = zf.read("AndroidManifest.xml")
                except Exception:
                    raw_manifest = b""

            ascii_text = re.findall(rb"[ -~]{4,120}", raw_manifest)
            joined_manifest = "\n".join(x.decode("latin-1", errors="ignore") for x in ascii_text).lower()

            if "usescleartexttraffic" in joined_manifest:
                findings.append({
                    "severity": "HIGH",
                    "title": "Cleartext Traffic Attribute Present in Manifest",
                    "risk": "Manifest references cleartext traffic configuration.",
                    "impact": "Network traffic over unencrypted HTTP could be intercepted on untrusted networks.",
                    "control": "Enforce HTTPS/TLS and configure network security policy to block cleartext traffic.",
                })
            if "debuggable" in joined_manifest:
                findings.append({
                    "severity": "HIGH",
                    "title": "Debuggable Flag Reference Detected in Manifest",
                    "risk": "Manifest contains debuggable attribute reference.",
                    "impact": "Debugging interfaces may expose internal state if enabled in release builds.",
                    "control": "Ensure release APKs are built with debugging disabled and signed for production.",
                })
            if "allowbackup" in joined_manifest:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Backup Attribute Reference Detected in Manifest",
                    "risk": "Manifest contains allowBackup configuration reference.",
                    "impact": "Application data may be included in device backups if not restricted.",
                    "control": "Review backup rules and exclude sensitive local storage where appropriate.",
                })

            suspicious_hits = []
            for entry in names[:120]:
                if entry.lower().endswith((".json", ".xml", ".txt", ".properties", ".yml", ".yaml")):
                    try:
                        data = zf.read(entry).decode("utf-8", errors="ignore")
                        if re.search(r"(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{6,}", data, re.I):
                            suspicious_hits.append(entry)
                    except Exception:
                        continue
            if suspicious_hits:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Potential Hardcoded Credential/Token Strings in Package Assets",
                    "risk": f"Pattern matches found in: {', '.join(suspicious_hits[:6])}",
                    "impact": "Embedded tokens or keys in client packages can be extracted statically.",
                    "control": "Move secrets to secure backend services and rotate exposed credentials.",
                })
    except Exception as exc:
        findings.append({
            "severity": "LOW",
            "title": "APK Archive Inspection Limitation",
            "risk": f"Unable to parse APK archive completely: {exc}",
            "impact": "Some internal entries could not be inspected.",
            "control": "Ensure the file is a valid intact APK archive.",
        })

    if not findings:
        findings.append({
            "severity": "LOW",
            "title": "No High-Risk Static Indicators Found in Quick Check",
            "risk": "No obvious manifest/asset risk markers surfaced in non-intrusive static check.",
            "impact": "Baseline static check completed without immediate high-severity flags.",
            "control": "Continue standard code review, dependency auditing, and authorized security testing.",
        })

    return {"meta": meta, "findings": findings}


def run_deep_posture_audit(target_input: str) -> dict:
    import urllib.request
    import urllib.error
    from urllib.parse import urljoin
    from concurrent.futures import ThreadPoolExecutor

    t = (target_input or "").strip()
    p_candidate = Path(t).expanduser()
    if t.lower().endswith(".apk") or p_candidate.is_file():
        apk_res = audit_apk_static(t)
        return {
            "kind": "APK_STATIC_AUDIT",
            "target": t,
            "apk_meta": apk_res["meta"],
            "findings": apk_res["findings"],
            "probes": [],
        }

    url = t if "://" in t else ("https://" + t if "." in t and "@" not in t else "")
    findings = []
    probes = []
    headers_map = {}

    if url:
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "coder4silnt-deep-auditor/1.0",
                    "Origin": "https://example.com",
                },
            )
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                headers_map = {k.lower(): v for k, v in resp.headers.items()}
                _ = resp.read(120000)
        except urllib.error.HTTPError as he:
            headers_map = {k.lower(): v for k, v in (he.headers.items() if he.headers else [])}
        except Exception as exc:
            findings.append({
                "severity": "LOW",
                "title": "Deep HTTP Probe Reachability Note",
                "risk": f"Direct request to '{url}' encountered: {exc}",
                "impact": "Remote HTTP headers could not be retrieved directly.",
                "control": "Verify network connectivity, domain resolution, and access permissions.",
            })

        if headers_map:
            if "strict-transport-security" not in headers_map:
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Missing HSTS (Strict-Transport-Security) Header",
                    "risk": "Response lacks Strict-Transport-Security header.",
                    "impact": "Clients may connect over plain HTTP on initial requests or downgrade attempts.",
                    "control": "Enable HSTS with appropriate max-age after verifying full HTTPS support.",
                })
            if "permissions-policy" not in headers_map:
                findings.append({
                    "severity": "LOW",
                    "title": "Missing Permissions-Policy Header",
                    "risk": "Response does not define Permissions-Policy browser feature restrictions.",
                    "impact": "Browser features such as camera, microphone, or geolocation lack explicit header restriction.",
                    "control": "Define Permissions-Policy to restrict unused browser APIs.",
                })
            acao = headers_map.get("access-control-allow-origin", "")
            acac = headers_map.get("access-control-allow-credentials", "").lower()
            if acao == "*" and acac == "true":
                findings.append({
                    "severity": "HIGH",
                    "title": "Permissive CORS Wildcard Combined With Credentials",
                    "risk": "Access-Control-Allow-Origin is '*' alongside Access-Control-Allow-Credentials: true.",
                    "impact": "Cross-origin credentialed requests could be exposed if misconfigured.",
                    "control": "Restrict Access-Control-Allow-Origin to explicit trusted origins rather than '*'.",
                })
            elif acao == "*":
                findings.append({
                    "severity": "MEDIUM",
                    "title": "Wildcard CORS Allow-Origin Header",
                    "risk": "Access-Control-Allow-Origin allows any origin ('*').",
                    "impact": "Public cross-origin reads are permitted on endpoints returning this header.",
                    "control": "Scope CORS origins tightly to required domains.",
                })

        check_paths = (
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
            "/api",
            "/swagger",
            "/openapi.json",
            "/graphql",
            "/admin",
            "/login",
        )

        def _probe(pth):
            full = urljoin(url.rstrip("/") + "/", pth.lstrip("/"))
            try:
                r = urllib.request.Request(full, headers={"User-Agent": "coder4silnt-deep-auditor/1.0"})
                with urllib.request.urlopen(r, timeout=2.5) as sp:
                    return {"path": pth, "status": getattr(sp, "status", 200)}
            except urllib.error.HTTPError as h_err:
                return {"path": pth, "status": h_err.code}
            except Exception:
                return {"path": pth, "status": None}

        with ThreadPoolExecutor(max_workers=6) as ex:
            probes = list(ex.map(_probe, check_paths))

        exposed_docs = [p["path"] for p in probes if p["status"] == 200 and p["path"] in ("/swagger", "/openapi.json", "/graphql")]
        if exposed_docs:
            findings.append({
                "severity": "MEDIUM",
                "title": "Publicly Accessible API Schema or Endpoint Index",
                "risk": f"Paths returning HTTP 200: {', '.join(exposed_docs)}",
                "impact": "API structure and routes are publicly discoverable without authentication.",
                "control": "Restrict internal/staging API documentation and schema endpoints where not intended for public use.",
            })
    else:
        findings.append({
            "severity": "LOW",
            "title": "Non-URL / Contact Identifier Deep Posture Note",
            "risk": f"Identifier '{t}' checked in non-intrusive posture mode.",
            "impact": "No active network exploit or private account lookup performed.",
            "control": "Combine with domain/email hygiene checks and authorized verification workflows.",
        })

    return {
        "kind": "DEEP_TARGET_AUDIT",
        "target": t,
        "apk_meta": None,
        "findings": findings,
        "probes": probes,
    }


def scan_local_wifi_devices() -> dict:
    import subprocess
    import shutil

    devices = []
    seen_ips = set()

    arp_file = Path("/proc/net/arp")
    if arp_file.is_file():
        for ln in arp_file.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
            parts = ln.split()
            if len(parts) >= 4:
                ip_addr, mac_addr, flags = parts[0], parts[3].lower(), parts[2]
                if mac_addr != "00:00:00:00:00:00" and ip_addr not in seen_ips:
                    seen_ips.add(ip_addr)
                    devices.append({"ip": ip_addr, "mac": mac_addr, "state": f"arp-flags:{flags}"})

    if not devices and shutil.which("ip"):
        try:
            proc = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=5)
            for ln in (proc.stdout or "").splitlines():
                parts = ln.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip_addr = parts[0]
                    mac_addr = parts[parts.index("lladdr") + 1].lower()
                    state = parts[-1]
                    if mac_addr != "00:00:00:00:00:00" and ip_addr not in seen_ips:
                        seen_ips.add(ip_addr)
                        devices.append({"ip": ip_addr, "mac": mac_addr, "state": state})
        except Exception:
            pass

    findings = []
    if not devices:
        findings.append({
            "severity": "LOW",
            "title": "No Active Neighbor Devices Found in ARP/Neighbor Cache",
            "risk": "Neighbor cache currently shows no active remote peer MAC entries.",
            "impact": "Local client inventory is empty or interface is isolated.",
            "control": "Ensure device is connected to target Wi-Fi or Hotspot and authorized for inspection.",
        })
    else:
        findings.append({
            "severity": "MEDIUM",
            "title": "Shared Local Network / Hotspot Peer Visibility",
            "risk": f"Detected {len(devices)} active local peer(s) on Wi-Fi/Hotspot neighbor table.",
            "impact": "Unsegmented local networks or hotspots can expose local services or allow lateral recon if access is open.",
            "control": "Use WPA2/WPA3 strong passphrases, enable client isolation where applicable, and audit connected hosts.",
        })
        if len(devices) >= 8:
            findings.append({
                "severity": "HIGH",
                "title": "High Number of Connected Peers on Local Segment",
                "risk": f"{len(devices)} hosts observed in local neighbor table.",
                "impact": "Larger shared LAN/hotspot occupancy increases exposure to unauthorized or rogue devices.",
                "control": "Review DHCP/hotspot client list, rotate shared Wi-Fi credentials, and restrict unknown MAC/IP access.",
            })

    return {"devices": devices, "findings": findings}


def main() -> None:
    parser = argparse.ArgumentParser(description="Coder4silnt Alpha Team CLI")
    parser.add_argument("--with-nmap", action="store_true", help="Include optional nmap summary on authorized targets")
    parser.add_argument("--batch", metavar="TARGETS_FILE", help="Run sequential scan from a targets file (one target per line)")
    args = parser.parse_args()
    if args.batch:
        print_alpha_header()
        run_batch_scan(args.batch, with_nmap=args.with_nmap)
    else:
        interactive_menu(with_nmap_default=args.with_nmap)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{GOLD}Interrupted.{RESET}")
        sys.exit(0)
