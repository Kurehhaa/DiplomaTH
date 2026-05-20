from datetime import datetime
from urllib.parse import urlparse
import socket
import requests


COMMON_PORTS = [22, 80, 443, 8080]


def normalize_target(target: str) -> str:
    target = target.strip()

    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.netloc

    return target


def resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def scan_ports(domain: str, ports: list[int] | None = None) -> list[int]:
    ports = ports or COMMON_PORTS
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()

    return open_ports


def fetch_http_metadata(domain: str) -> dict:
    metadata = {
        "reachable_url": None,
        "status_code": None,
        "server": "Unknown",
        "content_type": "Unknown",
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, timeout=4, allow_redirects=True)
            metadata["reachable_url"] = response.url
            metadata["status_code"] = response.status_code
            metadata["server"] = response.headers.get("Server", "Unknown")
            metadata["content_type"] = response.headers.get("Content-Type", "Unknown")
            return metadata
        except Exception:
            continue

    return metadata


def build_assets(domain: str, ip: str | None, open_ports: list[int], http_metadata: dict) -> list[dict]:
    assets = []

    if ip:
        assets.append({"type": "IP Address", "value": ip, "risk": "Low"})

    for port in open_ports:
        risk = "Low"
        if port == 22:
            risk = "Medium"
        elif port == 8080:
            risk = "Medium"
        elif port == 80:
            risk = "Medium"

        assets.append({"type": "Port", "value": f"{port}", "risk": risk})

    if http_metadata["server"] != "Unknown":
        assets.append(
            {
                "type": "Technology",
                "value": http_metadata["server"],
                "risk": "Medium",
            }
        )

    if http_metadata["reachable_url"]:
        assets.append(
            {
                "type": "URL",
                "value": http_metadata["reachable_url"],
                "risk": "Low",
            }
        )

    return assets


def build_findings(domain: str, ip: str | None, open_ports: list[int], http_metadata: dict) -> list[dict]:
    findings = []

    if 22 in open_ports:
        findings.append(
            {
                "title": "SSH Exposure Detected",
                "severity": "Medium",
                "score": 6.5,
                "description": "Port 22 is reachable from the network perimeter and may require access-control validation during pentesting.",
            }
        )

    if 80 in open_ports and 443 in open_ports:
        findings.append(
            {
                "title": "Multiple Web Entry Points",
                "severity": "Medium",
                "score": 6.8,
                "description": "Both HTTP and HTTPS services are exposed, increasing the observable web attack surface.",
            }
        )

    if http_metadata["server"] != "Unknown":
        findings.append(
            {
                "title": "Technology Fingerprint Available",
                "severity": "High",
                "score": 7.4,
                "description": f"The target exposes server fingerprint information ({http_metadata['server']}), which may support reconnaissance and vulnerability mapping.",
            }
        )

    if not ip:
        findings.append(
            {
                "title": "DNS Resolution Failed",
                "severity": "Low",
                "score": 3.0,
                "description": "The target could not be resolved during this scan attempt.",
            }
        )

    if not findings:
        findings.append(
            {
                "title": "Limited External Exposure",
                "severity": "Low",
                "score": 3.8,
                "description": "Only limited externally observable indicators were detected in the current scan scope.",
            }
        )

    return findings


def calculate_risk_score(open_ports: list[int], http_metadata: dict, findings: list[dict]) -> tuple[float, str]:
    score = 3.5

    if 22 in open_ports:
        score += 1.2
    if 80 in open_ports:
        score += 1.0
    if 443 in open_ports:
        score += 0.8
    if 8080 in open_ports:
        score += 1.3
    if http_metadata["server"] != "Unknown":
        score += 1.2
    if http_metadata["status_code"] and http_metadata["status_code"] < 500:
        score += 0.8

    score += min(len(findings) * 0.4, 1.5)
    score = min(round(score, 1), 10.0)

    if score >= 8.5:
        severity = "Critical"
    elif score >= 7.0:
        severity = "High"
    elif score >= 5.0:
        severity = "Medium"
    else:
        severity = "Low"

    return score, severity


def run_scan(target: str) -> dict:
    domain = normalize_target(target)
    ip = resolve_ip(domain)
    open_ports = scan_ports(domain) if ip else []
    http_metadata = fetch_http_metadata(domain) if ip else {
        "reachable_url": None,
        "status_code": None,
        "server": "Unknown",
        "content_type": "Unknown",
    }

    findings = build_findings(domain, ip, open_ports, http_metadata)
    assets = build_assets(domain, ip, open_ports, http_metadata)
    risk_score, severity = calculate_risk_score(open_ports, http_metadata, findings)

    detected_technologies = []
    if http_metadata["server"] != "Unknown":
        detected_technologies.append(http_metadata["server"])

    return {
        "target": domain,
        "status": "completed",
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "summary": {
            "subdomains": 0,
            "open_ports": len(open_ports),
            "detected_technologies": detected_technologies,
            "risk_score": risk_score,
            "severity": severity,
        },
        "assets": assets,
        "findings": findings,
    }