from typing import Dict, List

# Tech → CVE mapping database
VULN_DATABASE = {
    # ─── CMS ───────────────────────────────────────────────
    "WordPress": [
        {"cve": "CVE-2023-2745",  "description": "Directory traversal vulnerability", "severity": "High",     "cvss": 7.2},
        {"cve": "CVE-2022-21663", "description": "SQL injection via WP_Query",         "severity": "High",     "cvss": 8.0},
        {"cve": "CVE-2021-29447", "description": "XML External Entity injection",       "severity": "Medium",   "cvss": 6.5},
    ],
    "Joomla": [
        {"cve": "CVE-2023-23752", "description": "Improper access check allows info disclosure", "severity": "Medium", "cvss": 5.3},
        {"cve": "CVE-2022-23793", "description": "Path traversal vulnerability",                 "severity": "High",   "cvss": 7.5},
    ],
    "Drupal": [
        {"cve": "CVE-2022-25271", "description": "Improper input validation in core",    "severity": "High",     "cvss": 7.5},
        {"cve": "CVE-2020-13671", "description": "Remote code execution via file upload","severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2019-6340",  "description": "Drupalgeddon3 — RCE via REST API",    "severity": "Critical", "cvss": 9.8},
    ],
    "Shopify": [
        {"cve": "CVE-2022-21703", "description": "CSRF vulnerability in admin",          "severity": "Medium",   "cvss": 5.4},
    ],
    "Magento": [
        {"cve": "CVE-2022-24086", "description": "RCE via improper input validation",    "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2021-21024", "description": "Blind SQL injection via REST API",     "severity": "High",     "cvss": 7.5},
    ],

    # ─── WEB SERVERS ───────────────────────────────────────
    "Apache": [
        {"cve": "CVE-2021-41773", "description": "Path traversal and RCE",               "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2021-42013", "description": "Path traversal bypass",                "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2022-31813", "description": "Request smuggling vulnerability",       "severity": "High",     "cvss": 7.5},
    ],
    "Nginx": [
        {"cve": "CVE-2021-23017", "description": "DNS resolver buffer overflow",          "severity": "High",     "cvss": 7.7},
        {"cve": "CVE-2022-41741", "description": "Memory corruption vulnerability",       "severity": "High",     "cvss": 7.1},
        {"cve": "CVE-2017-7529",  "description": "Integer overflow in range filter",      "severity": "Medium",   "cvss": 5.3},
    ],
    "IIS": [
        {"cve": "CVE-2022-21907", "description": "HTTP protocol stack RCE",               "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2021-31166", "description": "HTTP protocol stack RCE",               "severity": "Critical", "cvss": 9.8},
    ],
    "LiteSpeed": [
        {"cve": "CVE-2022-0073",  "description": "Path traversal via crafted request",    "severity": "High",     "cvss": 7.5},
    ],

    # ─── LANGUAGES / RUNTIMES ──────────────────────────────
    "PHP": [
        {"cve": "CVE-2022-31625", "description": "Use after free vulnerability",          "severity": "High",     "cvss": 7.0},
        {"cve": "CVE-2023-0568",  "description": "Buffer overflow in core",               "severity": "High",     "cvss": 7.5},
        {"cve": "CVE-2021-21705", "description": "SSRF in FILTER_VALIDATE_URL",           "severity": "Medium",   "cvss": 5.0},
    ],
    "Java": [
        {"cve": "CVE-2021-44228", "description": "Log4Shell — RCE via JNDI lookup (Log4j)","severity": "Critical","cvss": 10.0},
        {"cve": "CVE-2022-22965", "description": "Spring4Shell — RCE via data binding",   "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2021-42392", "description": "H2 console JNDI RCE",                  "severity": "Critical", "cvss": 9.8},
    ],
    "Python": [
        {"cve": "CVE-2023-24329", "description": "URL parsing bypass via blank in scheme","severity": "High",     "cvss": 7.5},
        {"cve": "CVE-2021-3737",  "description": "Infinite loop in HTTP client DoS",      "severity": "Medium",   "cvss": 6.5},
    ],
    "Node.js": [
        {"cve": "CVE-2022-32215", "description": "HTTP request smuggling",                "severity": "High",     "cvss": 7.4},
        {"cve": "CVE-2021-22940", "description": "Use after free in TLS handling",        "severity": "High",     "cvss": 7.5},
    ],

    # ─── FRAMEWORKS ────────────────────────────────────────
    "Django": [
        {"cve": "CVE-2022-28347", "description": "SQL injection in QuerySet.explain()",  "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2022-28346", "description": "SQL injection in annotate()",           "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2021-35042", "description": "SQL injection via unsanitized input",   "severity": "Critical", "cvss": 9.8},
    ],
    "Laravel": [
        {"cve": "CVE-2021-3129",  "description": "RCE via debug mode + Ignition",         "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2022-30778", "description": "SSRF via redirect validation bypass",   "severity": "High",     "cvss": 7.5},
    ],
    "Flask": [
        {"cve": "CVE-2023-30861", "description": "Session cookie not invalidated on logout","severity": "High",   "cvss": 7.5},
        {"cve": "CVE-2018-1000656","description": "Denial of service via large JSON body", "severity": "Medium",  "cvss": 5.3},
    ],
    "Express.js": [
        {"cve": "CVE-2022-24999", "description": "Prototype pollution via qs library",    "severity": "High",     "cvss": 7.5},
        {"cve": "CVE-2021-23343", "description": "ReDoS in path-to-regexp",               "severity": "Medium",   "cvss": 5.3},
    ],
    "Spring Boot": [
        {"cve": "CVE-2022-22965", "description": "Spring4Shell — RCE via data binding",   "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2022-22963", "description": "SpEL injection in Spring Cloud Function","severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2021-22053", "description": "RCE via Thymeleaf template injection",  "severity": "High",     "cvss": 8.8},
    ],
    "ASP.NET": [
        {"cve": "CVE-2023-29331", "description": "Denial of service in .NET",             "severity": "High",     "cvss": 7.5},
        {"cve": "CVE-2021-26701", "description": "RCE in .NET 5/Core via text encoding",  "severity": "Critical", "cvss": 9.8},
    ],
    "Ruby on Rails": [
        {"cve": "CVE-2022-32224", "description": "RCE via YAML deserialization",          "severity": "Critical", "cvss": 9.8},
        {"cve": "CVE-2021-22885", "description": "Information disclosure in queries",     "severity": "High",     "cvss": 7.5},
    ],

    # ─── FRONTEND FRAMEWORKS ───────────────────────────────
    "React": [
        {"cve": "CVE-2018-6341",  "description": "XSS vulnerability in React DOM",        "severity": "Medium",   "cvss": 6.1},
    ],
    "Next.js": [
        {"cve": "CVE-2024-34351", "description": "SSRF via host header manipulation",     "severity": "High",     "cvss": 7.5},
        {"cve": "CVE-2023-46298", "description": "DoS via crafted HEAD request",          "severity": "Medium",   "cvss": 5.3},
    ],
    "Vue.js": [
        {"cve": "CVE-2021-3456",  "description": "XSS via v-html directive misuse",       "severity": "Medium",   "cvss": 6.1},
    ],
    "Angular": [
        {"cve": "CVE-2022-25869", "description": "XSS via bypassSecurityTrust*",          "severity": "Medium",   "cvss": 6.1},
        {"cve": "CVE-2019-10768", "description": "Prototype pollution via merge()",        "severity": "High",     "cvss": 7.5},
    ],
    "jQuery": [
        {"cve": "CVE-2020-11023", "description": "XSS via HTML passed to manipulation methods","severity": "Medium","cvss": 6.1},
        {"cve": "CVE-2020-11022", "description": "XSS via passing HTML to manipulation methods","severity": "Medium","cvss": 6.1},
        {"cve": "CVE-2019-11358", "description": "Prototype pollution via Object.extend", "severity": "Medium",   "cvss": 6.1},
    ],
    "Bootstrap": [
        {"cve": "CVE-2019-8331",  "description": "XSS in tooltip/popover data-template",  "severity": "Medium",   "cvss": 6.1},
        {"cve": "CVE-2018-14042", "description": "XSS in data-container property",        "severity": "Medium",   "cvss": 6.1},
    ],

    # ─── DATABASES ─────────────────────────────────────────
    "MySQL": [
        {"cve": "CVE-2022-21417", "description": "DoS via InnoDB unspecified vulnerability","severity": "Medium",  "cvss": 4.9},
        {"cve": "CVE-2021-2307",  "description": "Information disclosure via file read",   "severity": "Medium",   "cvss": 6.1},
    ],
    "MongoDB": [
        {"cve": "CVE-2021-32035", "description": "DoS via crafted aggregation pipeline",   "severity": "Medium",   "cvss": 5.3},
        {"cve": "CVE-2019-2392",  "description": "Memory corruption via crafted query",    "severity": "Medium",   "cvss": 6.5},
    ],
    "Redis": [
        {"cve": "CVE-2022-24736", "description": "DoS via crafted Lua script",             "severity": "Medium",   "cvss": 5.5},
        {"cve": "CVE-2022-0543",  "description": "Lua sandbox escape → RCE",               "severity": "Critical", "cvss": 10.0},
        {"cve": "CVE-2021-32761", "description": "Integer overflow in GETDEL command",     "severity": "High",     "cvss": 7.5},
    ],
    "Elasticsearch": [
        {"cve": "CVE-2021-22145", "description": "Memory disclosure via crafted search",   "severity": "Medium",   "cvss": 6.5},
        {"cve": "CVE-2020-7014",  "description": "Privilege escalation via field caps API","severity": "High",     "cvss": 8.8},
    ],

    # ─── CDN / SECURITY ────────────────────────────────────
    "Cloudflare": [
        {"cve": "N/A", "description": "WAF/CDN detected — origin IP bypass may expose real server", "severity": "Info", "cvss": 0.0},
    ],
    "AWS CloudFront": [
        {"cve": "N/A", "description": "CDN detected — check for S3 bucket misconfig behind distribution", "severity": "Info", "cvss": 0.0},
    ],
    "AWS S3": [
        {"cve": "N/A", "description": "S3 detected — check for public bucket access and listing", "severity": "Medium", "cvss": 5.0},
    ],

    # ─── BUILD TOOLS ───────────────────────────────────────
    "Webpack": [
        {"cve": "N/A", "description": "Source maps may expose original source code if not disabled", "severity": "Low", "cvss": 2.0},
    ],
    "GraphQL": [
        {"cve": "N/A", "description": "Introspection enabled — full schema enumeration possible",     "severity": "Medium", "cvss": 5.3},
        {"cve": "CVE-2023-32992", "description": "Denial of service via deeply nested queries",      "severity": "Medium", "cvss": 5.3},
    ],
}

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def correlate_vulnerabilities(detected_technologies: List[str]) -> Dict:
    findings = []
    total_score = 0.0

    for tech in detected_technologies:
        if tech in VULN_DATABASE:
            for vuln in VULN_DATABASE[tech]:
                findings.append({
                    "technology": tech,
                    "cve":         vuln["cve"],
                    "description": vuln["description"],
                    "severity":    vuln["severity"],
                    "cvss":        vuln["cvss"]
                })
                total_score += vuln["cvss"]

    # Sort by CVSS score descending
    findings.sort(key=lambda x: x["cvss"], reverse=True)

    critical = [f for f in findings if f["severity"] == "Critical"]
    high     = [f for f in findings if f["severity"] == "High"]
    medium   = [f for f in findings if f["severity"] == "Medium"]

    return {
        "total_findings":  len(findings),
        "critical_count":  len(critical),
        "high_count":      len(high),
        "medium_count":    len(medium),
        "findings":        findings,
        "risk_score":      round(total_score / len(findings), 2) if findings else 0.0
    }