def build_recommendations(open_ports: list[int], http_metadata: dict, ssl_info: dict) -> list[str]:
    recommendations = []

    if 21 in open_ports:
        recommendations.append("Review external FTP exposure and disable it if it is not required.")

    if 22 in open_ports:
        recommendations.append("Restrict SSH access using VPN, IP allow-listing, MFA, and strong authentication.")

    if 25 in open_ports:
        recommendations.append("Review SMTP exposure and ensure anti-abuse controls are configured.")

    if 445 in open_ports:
        recommendations.append("SMB should not be exposed to the public internet. Restrict access immediately.")

    if 3306 in open_ports:
        recommendations.append("Database ports should not be publicly exposed. Move database access behind private network controls.")

    if 3389 in open_ports:
        recommendations.append("RDP exposure is high risk. Restrict it using VPN, MFA, and network access controls.")

    if 8080 in open_ports:
        recommendations.append("Review services exposed on port 8080, especially admin panels and development interfaces.")

    if 80 in open_ports and 443 not in open_ports:
        recommendations.append("Enable HTTPS and redirect HTTP traffic to HTTPS.")

    if 80 in open_ports and 443 in open_ports:
        recommendations.append("Validate HTTP-to-HTTPS redirection and minimize duplicate web entry points.")

    if http_metadata.get("server") != "Unknown":
        recommendations.append("Reduce technology fingerprint disclosure by minimizing Server header details.")

    if http_metadata.get("x_powered_by") != "Unknown":
        recommendations.append("Remove or reduce X-Powered-By header disclosure.")

    security_headers = http_metadata.get("security_headers", {})

    if http_metadata.get("reachable_url"):
        if not security_headers.get("content_security_policy"):
            recommendations.append("Add Content-Security-Policy header to reduce client-side attack impact.")

        if not security_headers.get("x_frame_options"):
            recommendations.append("Add X-Frame-Options or CSP frame-ancestors protection.")

        if not security_headers.get("x_content_type_options"):
            recommendations.append("Add X-Content-Type-Options: nosniff header.")

    if ssl_info.get("enabled") and not ssl_info.get("valid"):
        recommendations.append("Renew or fix the invalid SSL certificate.")

    if ssl_info.get("expires_in_days") is not None and ssl_info["expires_in_days"] <= 30:
        recommendations.append("Renew SSL certificate before expiration.")

    if not recommendations:
        recommendations.append("Continue periodic external exposure monitoring and validate security controls.")

    return recommendations