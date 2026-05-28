# backend/app/scanner.py
import concurrent.futures
import datetime
import logging
import socket
import ssl
from typing import Dict, List, Optional
from urllib.parse import urlparse

import dns.resolver
import requests

from app.config import HIGH_RISK_PORTS, TOP_200_PORTS
from app.waf_service import detect_waf, waf_to_finding

logger = logging.getLogger(__name__)

# Баннеры: что отправить сервису чтобы он ответил
BANNER_PROBES = {
    21:   b"",           # FTP сам шлёт баннер
    22:   b"",           # SSH сам шлёт баннер
    23:   b"",           # Telnet сам шлёт баннер
    25:   b"EHLO x\r\n", # SMTP
    110:  b"",           # POP3 сам шлёт
    143:  b"",           # IMAP сам шлёт
    3306: b"",           # MySQL сам шлёт
    5432: b"",           # PostgreSQL
    6379: b"PING\r\n",   # Redis
    27017: b"",          # MongoDB
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}

# Порт → имя сервиса
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


# ─────────────────────────── УТИЛИТЫ ────────────────────────────

def normalize_target(target: str) -> str:
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        return urlparse(target).netloc.split(":")[0]
    return target.split("/")[0].split(":")[0]


def resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


# ─────────────────────────── ПОРТЫ ──────────────────────────────

def scan_ports(domain: str, max_ports: int = 100) -> List[int]:
    logger.info(f"Scanning top {max_ports} ports on {domain}")
    ports_to_scan = TOP_200_PORTS[:max_ports]

    def check_port(port: int) -> Optional[int]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.75)
        try:
            return port if sock.connect_ex((domain, port)) == 0 else None
        except OSError:
            return None
        finally:
            sock.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        results = list(executor.map(check_port, ports_to_scan))

    return sorted(r for r in results if r is not None)


# ─────────────────────────── BANNER GRABBING ────────────────────

def grab_banner(host: str, port: int, timeout: float = 3.0) -> Optional[str]:
    """
    Подключается к открытому порту и читает баннер сервиса.
    Возвращает первую значимую строку ответа или None.
    """
    probe = BANNER_PROBES.get(port, b"\r\n")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if probe:
            sock.sendall(probe)

        raw = sock.recv(1024)
        sock.close()

        if not raw:
            return None

        banner = raw.decode("utf-8", errors="ignore").strip()
        # Берём только первую строку, обрезаем мусор
        first_line = banner.split("\n")[0].strip()
        return first_line[:200] if first_line else None

    except OSError:
        return None


def grab_banners_parallel(host: str, open_ports: List[int]) -> Dict[int, str]:
    """Параллельно собирает баннеры со всех открытых портов."""
    results: Dict[int, str] = {}

    def _grab(port):
        return port, grab_banner(host, port)

    # Грабим только известные сервисные порты — не стоит слать probe на все
    target_ports = [p for p in open_ports if p in BANNER_PROBES or p < 1024]

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for port, banner in executor.map(_grab, target_ports):
            if banner:
                results[port] = banner
                logger.info(f"Banner [{port}]: {banner[:80]}")

    return results


def parse_version_from_banners(banners: Dict[int, str]) -> Dict[str, str]:
    """
    Извлекает версии технологий из баннеров.
    Возвращает словарь {технология: версия} для CVE lookup.
    """
    import re
    versions = {}

    for port, banner in banners.items():
        b = banner.lower()

        # SSH: "SSH-2.0-OpenSSH_8.9p1"
        m = re.search(r"ssh-[\d.]+-openssh[_\s]([\d.p]+)", b)
        if m:
            versions["openssh"] = m.group(1)

        # FTP: "220 vsftpd 3.0.3" / "220 FileZilla Server 0.9.60"
        m = re.search(r"220.*?vsftpd\s+([\d.]+)", b)
        if m:
            versions["vsftpd"] = m.group(1)

        m = re.search(r"220.*?filezilla.*?([\d.]+)", b)
        if m:
            versions["filezilla"] = m.group(1)

        # MySQL: "5.7.38-log" в первом пакете
        m = re.search(r"([\d]+\.[\d]+\.[\d]+).*?mysql", b)
        if m:
            versions["mysql"] = m.group(1)

        # Redis: "+PONG" или "-ERR" — версию из INFO не вытащить без доп. команды
        if port == 6379 and ("pong" in b or "redis" in b):
            versions["redis"] = "detected"

        # Apache / nginx из HTTP banner
        m = re.search(r"server:\s*(nginx|apache)[/\s]([\d.]+)", b)
        if m:
            versions[m.group(1)] = m.group(2)

    return versions


# ─────────────────────────── DNS РАЗВЕДКА ───────────────────────

def get_dns_records(domain: str) -> Dict:
    """
    Собирает DNS записи: A, AAAA, MX, NS, TXT, SPF, DMARC.
    Анализирует наличие защитных записей.
    """
    records: Dict = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            answers = resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            records[rtype] = []

    # SPF — ищем в TXT
    spf = [r for r in records.get("TXT", []) if "v=spf1" in r.lower()]
    records["SPF"] = spf

    # DMARC — отдельный запрос
    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        records["DMARC"] = [str(r) for r in dmarc_answers]
    except Exception:
        records["DMARC"] = []

    # DKIM — common selectors
    dkim_found = []
    for selector in ["default", "google", "mail", "k1", "dkim"]:
        try:
            resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            dkim_found.append(selector)
        except Exception:
            pass
    records["DKIM_selectors"] = dkim_found

    return records


def analyze_dns_security(dns_records: Dict) -> List[Dict]:
    """
    Анализирует DNS записи и возвращает findings связанные с email-безопасностью.
    """
    findings = []

    if not dns_records.get("SPF"):
        findings.append({
            "title": "Missing SPF Record",
            "severity": "Medium",
            "score": 6.0,
            "description": (
                "No SPF (Sender Policy Framework) record found. "
                "Attackers can spoof emails from this domain."
            ),
        })

    if not dns_records.get("DMARC"):
        findings.append({
            "title": "Missing DMARC Record",
            "severity": "Medium",
            "score": 6.5,
            "description": (
                "No DMARC policy found. Without DMARC, spoofed emails "
                "will be delivered to recipients with no enforcement action."
            ),
        })

    if not dns_records.get("DKIM_selectors"):
        findings.append({
            "title": "DKIM Not Detected",
            "severity": "Low",
            "score": 4.0,
            "description": (
                "No common DKIM selectors found. "
                "DKIM provides cryptographic email authentication."
            ),
        })

    # Проверяем политику DMARC если есть
    dmarc = " ".join(dns_records.get("DMARC", [])).lower()
    if dmarc and "p=none" in dmarc:
        findings.append({
            "title": "Weak DMARC Policy (p=none)",
            "severity": "Low",
            "score": 4.5,
            "description": (
                "DMARC policy is set to 'none' — monitoring only, no enforcement. "
                "Spoofed emails will still be delivered."
            ),
        })

    return findings


# ─────────────────────────── HTTP / SSL ─────────────────────────

def fetch_http_metadata(domain: str) -> Dict:
    metadata = {
        "reachable_url": None,
        "status_code": None,
        "server": "Unknown",
        "content_type": "Unknown",
        "x_powered_by": "Unknown",
        "security_headers": {},
        "robots_txt": None,
        "cms": None,
    }

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            r = requests.get(
                url,
                timeout=7,
                allow_redirects=True,
                headers={"User-Agent": "ThreatScope-Scanner/1.0"},
            )
            h = r.headers

            metadata.update({
                "reachable_url": r.url,
                "status_code": r.status_code,
                "server": h.get("Server", "Unknown"),
                "content_type": h.get("Content-Type", "Unknown"),
                "x_powered_by": h.get("X-Powered-By", "Unknown"),
                "security_headers": {
                    "strict_transport_security": h.get("Strict-Transport-Security"),
                    "content_security_policy": h.get("Content-Security-Policy"),
                    "x_frame_options": h.get("X-Frame-Options"),
                    "x_content_type_options": h.get("X-Content-Type-Options"),
                    "referrer_policy": h.get("Referrer-Policy"),
                    "permissions_policy": h.get("Permissions-Policy"),
                },
            })

            # Определяем CMS по признакам
            body = r.text[:5000].lower()
            if "wp-content" in body or "wp-json" in body:
                metadata["cms"] = "WordPress"
            elif "joomla" in body or "/components/com_" in body:
                metadata["cms"] = "Joomla"
            elif "drupal" in body or "sites/default/files" in body:
                metadata["cms"] = "Drupal"
            elif "shopify" in body:
                metadata["cms"] = "Shopify"

            # robots.txt
            try:
                robots = requests.get(
                    f"{scheme}://{domain}/robots.txt",
                    timeout=4,
                    headers={"User-Agent": "ThreatScope-Scanner/1.0"},
                )
                if robots.status_code == 200 and "user-agent" in robots.text.lower():
                    metadata["robots_txt"] = robots.text[:1000]
            except Exception:
                pass

            return metadata
        except Exception:
            continue

    return metadata


def get_ssl_info(domain: str) -> Dict:
    ssl_info = {
        "enabled": False,
        "valid": False,
        "expires_in_days": None,
        "issuer": None,
        "subject": None,
        "protocol": None,
        "self_signed": False,
    }
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(5)
            sock.connect((domain, 443))
            cert = sock.getpeercert()
            proto = sock.version()

            not_after = cert.get("notAfter")
            expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expire_date - datetime.datetime.utcnow()).days

            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            issuer_org = issuer_dict.get("organizationName", "Unknown")
            subject_org = subject_dict.get("organizationName", "Unknown")

            ssl_info.update({
                "enabled": True,
                "valid": days_left > 0,
                "expires_in_days": days_left,
                "issuer": issuer_org,
                "subject": subject_org,
                "protocol": proto,
                "self_signed": issuer_org == subject_org,
            })
    except Exception:
        pass
    return ssl_info


def discover_subdomains(domain: str, limit: int = 20) -> List[str]:
    subdomains: set = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=10,
        )
        if r.status_code == 200:
            for item in r.json():
                for name in item.get("name_value", "").split("\n"):
                    name = name.strip().lower().replace("*.", "")
                    if name.endswith(domain) and name != domain:
                        subdomains.add(name)
    except Exception:
        pass
    return sorted(subdomains)[:limit]


# ─────────────────────────── FINDINGS ───────────────────────────

def build_findings(scan_result: Dict) -> List[Dict]:
    findings: List[Dict] = []
    open_ports = scan_result["network"]["open_ports"]
    web = scan_result.get("web", {})
    ssl = scan_result.get("ssl", {})
    banners = scan_result.get("banners", {})
    security_headers = web.get("security_headers", {})

    # Высокорисковые порты
    for port in open_ports:
        if port in HIGH_RISK_PORTS:
            service = PORT_SERVICES.get(port, f"Port {port}")
            banner_info = f" — Banner: {banners[port]}" if port in banners else ""
            findings.append({
                "title": f"Exposed {service} Service (Port {port})",
                "severity": "High",
                "score": 8.5,
                "description": f"Externally accessible {service} on port {port}.{banner_info}",
            })

    # Server header
    server = web.get("server", "Unknown")
    if server and server != "Unknown":
        findings.append({
            "title": "Server Version Disclosure",
            "severity": "Medium",
            "score": 5.5,
            "description": f"Server header reveals: {server}. Attackers use this for targeted CVE lookup.",
        })

    # X-Powered-By
    xpb = web.get("x_powered_by", "Unknown")
    if xpb and xpb != "Unknown":
        findings.append({
            "title": "Technology Stack Disclosure (X-Powered-By)",
            "severity": "Low",
            "score": 3.5,
            "description": f"X-Powered-By header exposes: {xpb}.",
        })

    # Отсутствующие security headers
    missing_headers = {
        "strict_transport_security": ("Missing HSTS Header", 6.0),
        "content_security_policy":   ("Missing Content-Security-Policy", 5.5),
        "x_frame_options":           ("Missing X-Frame-Options (Clickjacking)", 5.0),
        "x_content_type_options":    ("Missing X-Content-Type-Options", 4.0),
    }
    for header_key, (title, score) in missing_headers.items():
        if not security_headers.get(header_key) and web.get("reachable_url"):
            findings.append({
                "title": title,
                "severity": "Low" if score < 5 else "Medium",
                "score": score,
                "description": f"The {header_key.replace('_', '-')} security header is absent.",
            })

    # SSL проблемы
    if ssl.get("enabled"):
        if ssl.get("self_signed"):
            findings.append({
                "title": "Self-Signed SSL Certificate",
                "severity": "High",
                "score": 7.5,
                "description": "The SSL certificate is self-signed and not trusted by browsers.",
            })
        days = ssl.get("expires_in_days")
        if days is not None and days <= 30:
            findings.append({
                "title": f"SSL Certificate Expiring Soon ({days} days)",
                "severity": "Medium" if days > 7 else "High",
                "score": 7.0 if days <= 7 else 5.5,
                "description": f"SSL certificate expires in {days} days. Service disruption imminent.",
            })
        if ssl.get("protocol") in ("TLSv1", "TLSv1.1", "SSLv3"):
            findings.append({
                "title": f"Outdated TLS Protocol ({ssl['protocol']})",
                "severity": "High",
                "score": 8.0,
                "description": f"Server supports {ssl['protocol']} which has known vulnerabilities (POODLE, BEAST).",
            })
    elif web.get("reachable_url") and web["reachable_url"].startswith("http://"):
        findings.append({
            "title": "No SSL/TLS Encryption",
            "severity": "High",
            "score": 8.0,
            "description": "Site is served over plain HTTP. All traffic is transmitted unencrypted.",
        })

    # CMS
    if web.get("cms"):
        findings.append({
            "title": f"CMS Detected: {web['cms']}",
            "severity": "Medium",
            "score": 5.0,
            "description": (
                f"{web['cms']} detected. CMS platforms have frequent critical vulnerabilities "
                "and require timely updates."
            ),
        })

    # robots.txt с чувствительными путями
    robots = web.get("robots_txt", "")
    if robots:
        sensitive_keywords = ["/admin", "/backup", "/config", "/api", "/private", "/secret"]
        exposed = [kw for kw in sensitive_keywords if kw in robots.lower()]
        if exposed:
            findings.append({
                "title": "Sensitive Paths in robots.txt",
                "severity": "Medium",
                "score": 5.5,
                "description": (
                    f"robots.txt discloses sensitive paths: {', '.join(exposed)}. "
                    "Attackers use this to target administrative interfaces."
                ),
            })

    # Версии из баннеров → предупреждение об устаревших сервисах
    versions = scan_result.get("banner_versions", {})
    for tech, version in versions.items():
        if version and version != "detected":
            findings.append({
                "title": f"Identified Service Version: {tech} {version}",
                "severity": "Info",
                "score": 3.0,
                "description": (
                    f"Banner grabbing identified {tech} version {version}. "
                    "This information enables targeted CVE lookup."
                ),
            })

    # Сортируем по score убыванию
    return sorted(findings, key=lambda x: x.get("score", 0), reverse=True)


# ─────────────────────────── ГЛАВНАЯ ФУНКЦИЯ ────────────────────

def start_recon_scan(target: str, fast_mode: bool = True) -> Dict:
    domain = normalize_target(target)
    logger.info(f"Starting reconnaissance for {domain}")

    max_ports = 80 if fast_mode else 180

    # 1. Базовые данные
    open_ports = scan_ports(domain, max_ports=max_ports)
    ip_address = resolve_ip(domain)

    # 2. Banner grabbing — параллельно
    banners = grab_banners_parallel(domain, open_ports)
    banner_versions = parse_version_from_banners(banners)
    logger.info(f"Banner versions found: {banner_versions}")

    # 3. HTTP, SSL, subdomains — параллельно
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_http   = executor.submit(fetch_http_metadata, domain)
        f_ssl    = executor.submit(get_ssl_info, domain)
        f_sub    = executor.submit(discover_subdomains, domain)
        f_dns    = executor.submit(get_dns_records, domain)
        f_waf    = executor.submit(detect_waf, domain)

        http_meta   = f_http.result()
        ssl_info    = f_ssl.result()
        subdomains  = f_sub.result()
        dns_records = f_dns.result()
        waf_result  = f_waf.result()

    # 4. Технологии для CVE (из заголовков + banner grabbing)
    technologies = []
    if http_meta.get("server") and http_meta["server"] != "Unknown":
        technologies.append(http_meta["server"])
    if http_meta.get("x_powered_by") and http_meta["x_powered_by"] != "Unknown":
        technologies.append(http_meta["x_powered_by"])
    for tech, ver in banner_versions.items():
        if ver and ver != "detected":
            technologies.append(f"{tech}/{ver}")

    scan_result = {
        "target": target,
        "domain": domain,
        "network": {
            "ip_address": ip_address,
            "open_ports": open_ports,
        },
        "web":     http_meta,
        "ssl":     ssl_info,
        "dns":     dns_records,
        "banners": banners,
        "banner_versions": banner_versions,
        "waf": waf_result,
        "technologies": technologies,
        "subdomains": subdomains,
        "summary": {
            "open_ports_count": len(open_ports),
            "subdomains_count": len(subdomains),
            "detected_technologies": technologies,
            "dns_issues": not bool(dns_records.get("SPF") and dns_records.get("DMARC")),
        },
        "findings": [],
        "recommendations": [],
        "scanned_at": datetime.datetime.now().isoformat(),
    }

    # 5. Findings: базовые + DNS
    dns_findings = analyze_dns_security(dns_records)
    waf_finding  = waf_to_finding(waf_result)
    extra = [waf_finding] if waf_finding else []
    scan_result["findings"] = build_findings(scan_result) + dns_findings + extra

    logger.info(
        f"Scan done | Ports: {len(open_ports)} | "
        f"Findings: {len(scan_result['findings'])} | "
        f"Banners: {len(banners)} | DNS issues: {len(dns_findings)}"
    )

    return scan_result
