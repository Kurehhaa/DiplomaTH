HIGH_RISK_PORTS = {
    21: "FTP service is externally exposed.",
    22: "SSH service is externally exposed.",
    25: "SMTP service is externally exposed.",
    445: "SMB service is externally exposed.",
    3306: "Database service is externally exposed.",
    3389: "Remote Desktop service is externally exposed.",
    8080: "Alternative web service is externally exposed.",
}


def build_findings(
    ip: str | None,
    open_ports: list[int],
    http_metadata: dict,
    ssl_info: dict,
    subdomains: list[str],
) -> list[dict]:
    findings = []

    if not ip:
        findings.append(
            {
                "title": "DNS Resolution Failed",
                "severity": "Low",
                "score": 3.0,
                "description": "The target could not be resolved to an IP address during the scan.",
            }
        )
        return findings

    for port, description in HIGH_RISK_PORTS.items():
        if port in open_ports:
            severity = "Critical" if port in [445, 3306, 3389] else "High"

            findings.append(
                {
                    "title": f"Exposed Service on Port {port}",
                    "severity": severity,
                    "score": 8.5 if severity == "Critical" else 7.4,
                    "description": description,
                }
            )

    if 80 in open_ports and 443 not in open_ports:
        findings.append(
            {
                "title": "HTTP Without HTTPS",
                "severity": "Medium",
                "score": 6.2,
                "description": "The target exposes HTTP but HTTPS was not detected on port 443.",
            }
        )

    if 80 in open_ports and 443 in open_ports:
        findings.append(
            {
                "title": "Multiple Web Entry Points",
                "severity": "Medium",
                "score": 6.0,
                "description": "Both HTTP and HTTPS are exposed, increasing the visible web attack surface.",
            }
        )

    if len(open_ports) >= 5:
        findings.append(
            {
                "title": "Large External Service Exposure",
                "severity": "High",
                "score": 7.8,
                "description": "Multiple services are reachable externally, which increases attack surface complexity.",
            }
        )

    if http_metadata.get("server") != "Unknown":
        findings.append(
            {
                "title": "Technology Fingerprint Disclosure",
                "severity": "Medium",
                "score": 6.7,
                "description": f"Server fingerprint is exposed: {http_metadata.get('server')}. This can help attackers map possible vulnerabilities.",
            }
        )

    if http_metadata.get("x_powered_by") != "Unknown":
        findings.append(
            {
                "title": "X-Powered-By Header Disclosure",
                "severity": "Medium",
                "score": 6.4,
                "description": f"Technology header is exposed: {http_metadata.get('x_powered_by')}.",
            }
        )

    security_headers = http_metadata.get("security_headers", {})

    if http_metadata.get("reachable_url"):
        if not security_headers.get("content_security_policy"):
            findings.append(
                {
                    "title": "Missing Content Security Policy",
                    "severity": "Low",
                    "score": 4.2,
                    "description": "Content-Security-Policy header was not detected.",
                }
            )

        if not security_headers.get("x_frame_options"):
            findings.append(
                {
                    "title": "Missing X-Frame-Options Header",
                    "severity": "Low",
                    "score": 4.0,
                    "description": "X-Frame-Options header was not detected.",
                }
            )

        if not security_headers.get("x_content_type_options"):
            findings.append(
                {
                    "title": "Missing X-Content-Type-Options Header",
                    "severity": "Low",
                    "score": 4.0,
                    "description": "X-Content-Type-Options header was not detected.",
                }
            )

    if ssl_info.get("enabled") is False and 443 in open_ports:
        findings.append(
            {
                "title": "SSL/TLS Information Unavailable",
                "severity": "Medium",
                "score": 5.8,
                "description": "HTTPS port is open but SSL certificate information could not be collected.",
            }
        )

    if ssl_info.get("enabled") and not ssl_info.get("valid"):
        findings.append(
            {
                "title": "Invalid or Expired SSL Certificate",
                "severity": "High",
                "score": 7.5,
                "description": "The SSL certificate appears to be invalid or expired.",
            }
        )

    if ssl_info.get("expires_in_days") is not None and ssl_info["expires_in_days"] <= 30:
        findings.append(
            {
                "title": "SSL Certificate Expiring Soon",
                "severity": "Medium",
                "score": 5.9,
                "description": f"SSL certificate expires in {ssl_info['expires_in_days']} days.",
            }
        )

    if len(subdomains) >= 10:
        findings.append(
            {
                "title": "Large Subdomain Exposure",
                "severity": "Medium",
                "score": 6.5,
                "description": "Multiple subdomains were discovered from certificate transparency logs.",
            }
        )

    if not findings:
        findings.append(
            {
                "title": "Limited External Exposure",
                "severity": "Low",
                "score": 3.8,
                "description": "Only limited externally observable indicators were detected.",
            }
        )

    return findings


def calculate_risk_score(
    open_ports: list[int],
    http_metadata: dict,
    ssl_info: dict,
    subdomains: list[str],
    findings: list[dict],
) -> tuple[float, str]:
    score = 2.0

    port_weights = {
        21: 1.2,
        22: 1.5,
        25: 1.1,
        53: 0.7,
        80: 0.8,
        110: 1.0,
        143: 1.0,
        443: 0.5,
        445: 2.0,
        3306: 2.0,
        3389: 2.2,
        8080: 1.6,
    }

    for port in open_ports:
        score += port_weights.get(port, 0.5)

    if http_metadata.get("server") != "Unknown":
        score += 0.8

    if http_metadata.get("x_powered_by") != "Unknown":
        score += 0.7

    if http_metadata.get("reachable_url"):
        score += 0.5

    if ssl_info.get("enabled") and not ssl_info.get("valid"):
        score += 1.4

    if ssl_info.get("expires_in_days") is not None and ssl_info["expires_in_days"] <= 30:
        score += 0.8

    if len(subdomains) >= 10:
        score += 0.8

    critical_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    medium_count = sum(1 for f in findings if f.get("severity") == "Medium")

    score += critical_count * 1.4
    score += high_count * 0.9
    score += medium_count * 0.4

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