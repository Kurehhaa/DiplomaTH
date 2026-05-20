from datetime import datetime, timezone
import re

import requests


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SEARCH_LIMIT = 20
RESULT_LIMIT_PER_TECHNOLOGY = 8

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}

PRODUCT_TERMS = {
    "nginx": ["nginx"],
    "apache": ["apache http server", "apache httpd", "httpd", "apache"],
    "php": ["php"],
    "express": ["express", "express.js", "expressjs"],
    "iis": ["microsoft iis", "internet information services", "iis"],
}

APACHE_NON_HTTP_PRODUCTS = [
    "apache activemq",
    "apache airflow",
    "apache cassandra",
    "apache couchdb",
    "apache druid",
    "apache flink",
    "apache kafka",
    "apache log4j",
    "apache solr",
    "apache spark",
    "apache struts",
    "apache superset",
    "apache tomcat",
]


def _strip_os_labels(value: str) -> str:
    value = re.sub(r"\([^)]*\)", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _clean_version(value: str | None) -> str | None:
    if not value:
        return None

    match = re.search(r"\b\d+(?:\.\d+){0,3}(?:[-+~][A-Za-z0-9.]+)?\b", value)
    if not match:
        return None

    return match.group(0).strip(".-+~")


def parse_technology(technology: str):
    """
    Extract a normalized product and clean version from common HTTP headers.

    Examples:
    nginx/1.29.3 (Ubuntu) -> (nginx, 1.29.3)
    Apache/2.4.58 -> (apache, 2.4.58)
    Microsoft-IIS/10.0 -> (iis, 10.0)
    """
    clean = _strip_os_labels(str(technology or "").strip())
    lowered = clean.lower()

    if not lowered:
        return "", None

    if "/" in lowered:
        product_part, version_part = lowered.split("/", 1)
        product = normalize_product(product_part)
        version = _clean_version(version_part)
        return product, version

    version = _clean_version(lowered)
    if version:
        product_part = lowered.split(version, 1)[0]
    else:
        product_part = lowered

    return normalize_product(product_part), version


def normalize_product(product: str):
    normalized = _strip_os_labels(str(product or "").lower())
    normalized = normalized.replace("_", " ").replace("-", " ")
    normalized = re.sub(r"[^a-z0-9. ]+", " ", normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()

    if "microsoft iis" in normalized or normalized == "iis":
        return "iis"
    if "internet information services" in normalized:
        return "iis"
    if "nginx" in normalized:
        return "nginx"
    if "apache" in normalized or normalized == "httpd":
        return "apache"
    if "php" in normalized:
        return "php"
    if "express" in normalized:
        return "express"

    return normalized


def _major_minor(version: str | None) -> str | None:
    if not version:
        return None

    parts = version.split(".")
    if len(parts) < 2:
        return None

    major_minor = ".".join(parts[:2])
    return major_minor if major_minor != version else None


def _build_search_queries(product: str, version: str | None) -> list[str]:
    queries = []

    if version:
        queries.append(f"{product} {version}")

    major_minor = _major_minor(version)
    if major_minor:
        queries.append(f"{product} {major_minor}")

    queries.append(product)

    deduped = []
    seen = set()
    for query in queries:
        if query not in seen:
            seen.add(query)
            deduped.append(query)

    return deduped


def fetch_cve_from_nvd(query: str, limit: int = SEARCH_LIMIT):
    params = {
        "keywordSearch": query,
        "resultsPerPage": limit,
    }

    try:
        res = requests.get(NVD_URL, params=params, timeout=10)

        if res.status_code != 200:
            return []

        data = res.json()
        return [_parse_nvd_item(item) for item in data.get("vulnerabilities", [])]

    except Exception as e:
        print("CVE error:", e)
        return []


def _parse_nvd_item(item: dict) -> dict:
    cve = item.get("cve", {})
    metrics = cve.get("metrics", {})
    severity, cvss = _extract_cvss(metrics)

    return {
        "cve_id": cve.get("id"),
        "severity": severity,
        "cvss": cvss,
        "description": _extract_english_description(cve),
        "published": cve.get("published"),
        "source": "NVD",
    }


def _extract_english_description(cve: dict) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return description.get("value", "")
    return ""


def _extract_cvss(metrics: dict) -> tuple[str, float | None]:
    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_items = metrics.get(metric_key)
        if not metric_items:
            continue

        metric = metric_items[0]
        cvss_data = metric.get("cvssData", {})
        score = cvss_data.get("baseScore")
        severity = cvss_data.get("baseSeverity") or metric.get("baseSeverity")

        if not severity and score is not None:
            severity = _severity_from_score(score)

        return (severity or "UNKNOWN").upper(), score

    return "UNKNOWN", None


def _severity_from_score(score: float) -> str:
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    return "LOW"


def _parse_nvd_date(value: str | None) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _is_recent(published: str | None, years: int = 5) -> bool:
    published_date = _parse_nvd_date(published)
    if published_date == datetime.min.replace(tzinfo=timezone.utc):
        return False

    now = datetime.now(timezone.utc)
    return (now - published_date).days <= years * 365


def is_relevant_cve(product: str, description: str):
    desc = description.lower()
    terms = PRODUCT_TERMS.get(product, [product])

    if not any(term in desc for term in terms):
        return False

    if product == "apache":
        has_http_context = "apache http server" in desc or "apache httpd" in desc
        has_false_project = any(name in desc for name in APACHE_NON_HTTP_PRODUCTS)
        if has_false_project and not has_http_context:
            return False

    # Avoid very old branch noise when no specific version relation is present.
    if "before 1." in desc or "before 0." in desc:
        return False

    return True


def filter_cves(product, version, cves):
    filtered = []
    seen = set()

    for cve in cves:
        cve_id = cve.get("cve_id")
        if not cve_id or cve_id in seen:
            continue

        description = cve.get("description") or ""
        if not description:
            continue

        if not is_relevant_cve(product, description):
            continue

        severity = (cve.get("severity") or "UNKNOWN").upper()
        cvss = cve.get("cvss") or 0

        if severity not in ["CRITICAL", "HIGH"]:
            if not (severity == "MEDIUM" and cvss >= 6 and _is_recent(cve.get("published"), years=3)):
                continue

        cve["severity"] = severity
        seen.add(cve_id)
        filtered.append(cve)

    return sort_cves(filtered)[:RESULT_LIMIT_PER_TECHNOLOGY]


def sort_cves(cves: list[dict]) -> list[dict]:
    return sorted(
        cves,
        key=lambda cve: (
            SEVERITY_ORDER.get((cve.get("severity") or "UNKNOWN").upper(), 0),
            cve.get("cvss") or 0,
            _parse_nvd_date(cve.get("published")),
        ),
        reverse=True,
    )


def get_cve_data(technologies: list[str]):
    all_results_by_id = {}

    for tech in technologies:
        product, version = parse_technology(tech)

        if not product:
            continue

        matched_cves = []
        for query in _build_search_queries(product, version):
            raw_cves = fetch_cve_from_nvd(query)
            matched_cves = filter_cves(product, version, raw_cves)

            if matched_cves:
                break

        for cve in matched_cves:
            cve_id = cve.get("cve_id")
            if not cve_id:
                continue

            enriched = {
                **cve,
                "technology": product,
                "product": product,
                "version": version,
                "raw_technology": tech,
            }

            existing = all_results_by_id.get(cve_id)
            if not existing or _cve_sort_tuple(enriched) > _cve_sort_tuple(existing):
                all_results_by_id[cve_id] = enriched

    return sort_cves(list(all_results_by_id.values()))


def _cve_sort_tuple(cve: dict) -> tuple:
    return (
        SEVERITY_ORDER.get((cve.get("severity") or "UNKNOWN").upper(), 0),
        cve.get("cvss") or 0,
        _parse_nvd_date(cve.get("published")),
    )


def summarize_cve_risk(cve_data):
    critical = sum(1 for c in cve_data if c["severity"] == "CRITICAL")
    high = sum(1 for c in cve_data if c["severity"] == "HIGH")

    if critical:
        risk = "Critical"
    elif high:
        risk = "High"
    else:
        risk = "Low"

    return {
        "total": len(cve_data),
        "critical": critical,
        "high": high,
        "risk_level": risk,
    }
