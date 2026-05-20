# backend/app/scanner.py
from urllib.parse import urlparse
import socket
import ssl
import datetime
import requests
import logging
import concurrent.futures
from typing import Dict, List

from app.config import TOP_200_PORTS, HIGH_RISK_PORTS

logger = logging.getLogger(__name__)


def normalize_target(target: str) -> str:
    target = target.strip().lower()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        return parsed.netloc.split(":")[0]
    return target.split("/")[0].split(":")[0]


def resolve_ip(domain: str):
    try:
        return socket.gethostbyname(domain)
    except:
        return None


def scan_ports(domain: str, max_ports: int = 100) -> List[int]:
    """Оптимизированное параллельное сканирование"""
    logger.info(f"Scanning top {max_ports} ports on {domain} (parallel)")

    open_ports = []
    ports_to_scan = TOP_200_PORTS[:max_ports]

    def check_port(port: int) -> int | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.75)                    # уменьшенный таймаут
        try:
            if sock.connect_ex((domain, port)) == 0:
                return port
        except:
            pass
        finally:
            sock.close()
        return None

    # Параллельное сканирование
    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
        results = executor.map(check_port, ports_to_scan)
        for result in results:
            if result is not None:
                open_ports.append(result)

    return sorted(open_ports)


def fetch_http_metadata(domain: str) -> Dict:
    metadata = {
        "reachable_url": None,
        "status_code": None,
        "server": "Unknown",
        "content_type": "Unknown",
        "x_powered_by": "Unknown",
    }

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{domain}"
            r = requests.get(
                url,
                timeout=7,
                allow_redirects=True,
                headers={"User-Agent": "ThreatScope-Scanner/1.0"}
            )
            metadata.update({
                "reachable_url": r.url,
                "status_code": r.status_code,
                "server": r.headers.get("Server", "Unknown"),
                "content_type": r.headers.get("Content-Type", "Unknown"),
                "x_powered_by": r.headers.get("X-Powered-By", "Unknown"),
            })
            return metadata
        except:
            continue
    return metadata


def get_ssl_info(domain: str) -> Dict:
    ssl_info = {"enabled": False, "valid": False, "expires_in_days": None}
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(5)
            sock.connect((domain, 443))
            cert = sock.getpeercert()
            not_after = cert.get("notAfter")
            if not_after:
                expire_date = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire_date - datetime.datetime.utcnow()).days
                ssl_info = {
                    "enabled": True,
                    "valid": days_left > 0,
                    "expires_in_days": days_left
                }
    except:
        pass
    return ssl_info


def discover_subdomains(domain: str, limit=20) -> List[str]:
    subdomains = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=10)
        if r.status_code == 200:
            for item in r.json():
                for name in item.get("name_value", "").split("\n"):
                    name = name.strip().lower().replace("*.","")
                    if name.endswith(domain) and name != domain:
                        subdomains.add(name)
    except:
        pass
    return sorted(list(subdomains))[:limit]


def build_findings_and_assets(scan_result: Dict) -> None:
    open_ports = scan_result["network"]["open_ports"]
    web = scan_result.get("web", {})

    findings = []

    # High risk ports
    for port in open_ports:
        if port in HIGH_RISK_PORTS:
            service = {21:"FTP", 22:"SSH", 23:"Telnet", 445:"SMB", 
                      3389:"RDP", 3306:"MySQL", 5432:"PostgreSQL", 
                      5900:"VNC"}.get(port, f"Port {port}")
            
            findings.append({
                "title": f"High Risk Port {port} ({service})",
                "severity": "High",
                "score": 8.5,
                "description": f"Externally exposed {service} service"
            })

    if web.get("server") and web.get("server") != "Unknown":
        findings.append({
            "title": "Server Header Disclosure",
            "severity": "Medium",
            "score": 6.5,
            "description": f"Server header exposed: {web['server']}"
        })

    scan_result["findings"] = findings
    scan_result["recommendations"] = [
        "Check exposed high-risk services for known vulnerabilities",
        "Consider hiding server headers",
        "Review SSL/TLS certificate expiration",
        "Implement proper firewall rules"
    ]


def start_recon_scan(target: str, fast_mode: bool = True) -> Dict:
    """Главная функция сканирования"""
    domain = normalize_target(target)
    logger.info(f"Starting reconnaissance for {domain} (fast_mode={fast_mode})")

    max_ports = 80 if fast_mode else 180   # можно регулировать

    scan_result = {
        "target": target,
        "domain": domain,
        "network": {
            "ip_address": resolve_ip(domain),
            "open_ports": scan_ports(domain, max_ports=max_ports)
        },
        "web": fetch_http_metadata(domain),
        "ssl": get_ssl_info(domain),
        "subdomains": discover_subdomains(domain),
        "summary": {},
        "findings": [],
        "assets": [],
        "recommendations": [],
        "scanned_at": datetime.datetime.now().isoformat()
    }

    scan_result["summary"] = {
        "open_ports_count": len(scan_result["network"]["open_ports"]),
        "subdomains_count": len(scan_result["subdomains"]),
        "detected_technologies": [scan_result["web"].get("server", "Unknown")]
    }

    build_findings_and_assets(scan_result)

    return scan_result