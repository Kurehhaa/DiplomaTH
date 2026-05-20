from urllib.parse import urlparse
import socket
import ssl
import datetime
import requests


COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    8080,  # HTTP alternate
]


def normalize_target(target: str) -> str:
    target = target.strip()

    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.netloc.split(":")[0]

    return target.split("/")[0].split(":")[0]


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
        sock.settimeout(0.8)

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
        "x_powered_by": "Unknown",
        "security_headers": {
            "strict_transport_security": False,
            "content_security_policy": False,
            "x_frame_options": False,
            "x_content_type_options": False,
        },
    }

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"

        try:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "ThreatScope-Scanner/1.0"},
            )

            headers = response.headers

            metadata["reachable_url"] = response.url
            metadata["status_code"] = response.status_code
            metadata["server"] = headers.get("Server", "Unknown")
            metadata["content_type"] = headers.get("Content-Type", "Unknown")
            metadata["x_powered_by"] = headers.get("X-Powered-By", "Unknown")

            metadata["security_headers"] = {
                "strict_transport_security": "Strict-Transport-Security" in headers,
                "content_security_policy": "Content-Security-Policy" in headers,
                "x_frame_options": "X-Frame-Options" in headers,
                "x_content_type_options": "X-Content-Type-Options" in headers,
            }

            return metadata

        except Exception:
            continue

    return metadata


def get_ssl_info(domain: str) -> dict:
    ssl_info = {
        "enabled": False,
        "valid": False,
        "issuer": "Unknown",
        "expires_at": None,
        "expires_in_days": None,
    }

    try:
        context = ssl.create_default_context()

        with context.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(5)
            sock.connect((domain, 443))
            cert = sock.getpeercert()

        not_after = cert.get("notAfter")

        if not_after:
            expire_date = datetime.datetime.strptime(
                not_after,
                "%b %d %H:%M:%S %Y %Z",
            )

            days_left = (expire_date - datetime.datetime.utcnow()).days

            ssl_info["enabled"] = True
            ssl_info["valid"] = days_left > 0
            ssl_info["expires_at"] = expire_date.strftime("%Y-%m-%d")
            ssl_info["expires_in_days"] = days_left

        issuer = cert.get("issuer", [])
        if issuer:
            issuer_parts = []
            for item in issuer:
                for key, value in item:
                    issuer_parts.append(f"{key}={value}")
            ssl_info["issuer"] = ", ".join(issuer_parts)

    except Exception:
        pass

    return ssl_info


def discover_subdomains(domain: str, limit: int = 20) -> list[str]:
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()

        for item in data:
            name_value = item.get("name_value", "")

            for name in name_value.split("\n"):
                name = name.strip().lower().replace("*.", "")

                if name.endswith(domain) and name != domain:
                    subdomains.add(name)

    except Exception:
        return []

    return sorted(list(subdomains))[:limit]


def detect_technologies(http_metadata: dict) -> list[str]:
    technologies = []

    server = http_metadata.get("server")
    x_powered_by = http_metadata.get("x_powered_by")

    if server and server != "Unknown":
        technologies.append(server)

    if x_powered_by and x_powered_by != "Unknown":
        technologies.append(x_powered_by)

    return technologies


def build_assets(
    ip: str | None,
    open_ports: list[int],
    http_metadata: dict,
    ssl_info: dict,
    subdomains: list[str],
) -> list[dict]:
    assets = []

    if ip:
        assets.append(
            {
                "type": "IP Address",
                "value": ip,
                "risk": "Low",
            }
        )

    for port in open_ports:
        risk = "Low"

        if port in [21, 22, 25, 445, 3306, 3389, 8080]:
            risk = "High"
        elif port in [80, 443]:
            risk = "Medium"

        assets.append(
            {
                "type": "Open Port",
                "value": str(port),
                "risk": risk,
            }
        )

    if http_metadata.get("reachable_url"):
        assets.append(
            {
                "type": "Reachable URL",
                "value": http_metadata["reachable_url"],
                "risk": "Low",
            }
        )

    if http_metadata.get("server") != "Unknown":
        assets.append(
            {
                "type": "Technology Fingerprint",
                "value": http_metadata["server"],
                "risk": "Medium",
            }
        )

    if http_metadata.get("x_powered_by") != "Unknown":
        assets.append(
            {
                "type": "Technology Header",
                "value": http_metadata["x_powered_by"],
                "risk": "Medium",
            }
        )

    if ssl_info.get("enabled"):
        assets.append(
            {
                "type": "SSL Certificate",
                "value": f"Valid: {ssl_info.get('valid')}, expires: {ssl_info.get('expires_at')}",
                "risk": "Low" if ssl_info.get("valid") else "High",
            }
        )

    for subdomain in subdomains:
        assets.append(
            {
                "type": "Subdomain",
                "value": subdomain,
                "risk": "Low",
            }
        )

    return assets