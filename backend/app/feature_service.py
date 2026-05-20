def extract_features(
    ip,
    open_ports,
    http_metadata,
    ssl_info,
    subdomains,
    findings,
):
    features = {}

    features["has_ip"] = 1 if ip else 0

    features["port_count"] = len(open_ports)
    features["has_21"] = 1 if 21 in open_ports else 0
    features["has_22"] = 1 if 22 in open_ports else 0
    features["has_25"] = 1 if 25 in open_ports else 0
    features["has_53"] = 1 if 53 in open_ports else 0
    features["has_80"] = 1 if 80 in open_ports else 0
    features["has_443"] = 1 if 443 in open_ports else 0
    features["has_445"] = 1 if 445 in open_ports else 0
    features["has_3306"] = 1 if 3306 in open_ports else 0
    features["has_3389"] = 1 if 3389 in open_ports else 0
    features["has_8080"] = 1 if 8080 in open_ports else 0

    features["has_http"] = 1 if http_metadata.get("reachable_url") else 0
    features["status_ok"] = (
        1
        if http_metadata.get("status_code") and http_metadata.get("status_code") < 500
        else 0
    )

    features["has_server_fingerprint"] = (
        1 if http_metadata.get("server") != "Unknown" else 0
    )

    features["has_x_powered_by"] = (
        1 if http_metadata.get("x_powered_by") != "Unknown" else 0
    )

    security_headers = http_metadata.get("security_headers", {})

    features["has_hsts"] = 1 if security_headers.get("strict_transport_security") else 0
    features["has_csp"] = 1 if security_headers.get("content_security_policy") else 0
    features["has_x_frame_options"] = 1 if security_headers.get("x_frame_options") else 0
    features["has_x_content_type_options"] = (
        1 if security_headers.get("x_content_type_options") else 0
    )

    features["ssl_enabled"] = 1 if ssl_info.get("enabled") else 0
    features["ssl_valid"] = 1 if ssl_info.get("valid") else 0
    features["ssl_expires_soon"] = (
        1
        if ssl_info.get("expires_in_days") is not None
        and ssl_info.get("expires_in_days") <= 30
        else 0
    )

    features["subdomain_count"] = len(subdomains)
    features["finding_count"] = len(findings)

    features["critical_findings"] = sum(
        1 for f in findings if f.get("severity") == "Critical"
    )
    features["high_findings"] = sum(
        1 for f in findings if f.get("severity") == "High"
    )
    features["medium_findings"] = sum(
        1 for f in findings if f.get("severity") == "Medium"
    )

    return features