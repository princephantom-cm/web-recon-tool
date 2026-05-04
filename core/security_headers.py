import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
from typing import Dict, List
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "HSTS — forces HTTPS connections",
        "missing_severity": "High",
        "missing_impact": "Site accessible over HTTP, MITM attack possible"
    },
    "Content-Security-Policy": {
        "description": "CSP — prevents XSS and injection attacks",
        "missing_severity": "High",
        "missing_impact": "No XSS protection, inline scripts allowed"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "missing_severity": "Medium",
        "missing_impact": "Site can be embedded in iframe — clickjacking possible"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "missing_severity": "Medium",
        "missing_impact": "Browser may execute files with wrong MIME type"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information sent",
        "missing_severity": "Low",
        "missing_impact": "Sensitive URLs may leak via Referrer header"
    },
    "Permissions-Policy": {
        "description": "Controls browser features (camera, mic, etc)",
        "missing_severity": "Low",
        "missing_impact": "Browser features not restricted"
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter for older browsers",
        "missing_severity": "Low",
        "missing_impact": "No XSS protection on older browsers"
    },
    "Cache-Control": {
        "description": "Controls caching behavior",
        "missing_severity": "Low",
        "missing_impact": "Sensitive data may be cached by browser/proxy"
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Controls cross-origin resource embedding",
        "missing_severity": "Medium",
        "missing_impact": "Cross-origin isolation not enforced"
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Protects against cross-origin window attacks",
        "missing_severity": "Medium",
        "missing_impact": "Window opener access not restricted"
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Controls cross-origin resource loading",
        "missing_severity": "Low",
        "missing_impact": "Resources loadable from any origin"
    },
    "Access-Control-Allow-Origin": {
        "description": "CORS policy — controls cross-origin requests",
        "missing_severity": "Info",
        "missing_impact": "CORS not explicitly configured"
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Controls Adobe Flash/PDF cross-domain access",
        "missing_severity": "Low",
        "missing_impact": "Flash/PDF cross-domain access not restricted"
    },
    "Expect-CT": {
        "description": "Certificate Transparency enforcement",
        "missing_severity": "Low",
        "missing_impact": "Misissued certificates may not be detected"
    },
    "Public-Key-Pins": {
        "description": "HTTP Public Key Pinning (HPKP)",
        "missing_severity": "Info",
        "missing_impact": "Certificate pinning not enforced"
    },
    "Feature-Policy": {
        "description": "Legacy browser feature control (replaced by Permissions-Policy)",
        "missing_severity": "Info",
        "missing_impact": "Older browsers features not restricted"
    },
    "X-Download-Options": {
        "description": "Prevents IE from executing downloaded files",
        "missing_severity": "Low",
        "missing_impact": "IE may auto-execute downloaded files"
    },
    "X-DNS-Prefetch-Control": {
        "description": "Controls DNS prefetching",
        "missing_severity": "Info",
        "missing_impact": "DNS prefetch may leak visited URLs"
    },
    "Timing-Allow-Origin": {
        "description": "Controls resource timing information exposure",
        "missing_severity": "Info",
        "missing_impact": "Resource timing data may be exposed"
    },
    "Clear-Site-Data": {
        "description": "Clears browsing data on logout",
        "missing_severity": "Info",
        "missing_impact": "Browser data not cleared on logout"
    },
    "Origin-Agent-Cluster": {
        "description": "Requests origin-keyed agent clustering",
        "missing_severity": "Info",
        "missing_impact": "Process isolation not requested"
    },
    "X-Robots-Tag": {
        "description": "Controls search engine indexing",
        "missing_severity": "Info",
        "missing_impact": "Sensitive pages may be indexed by search engines"
    },
    "NEL": {
        "description": "Network Error Logging policy",
        "missing_severity": "Info",
        "missing_impact": "Network errors not logged"
    },
    "Report-To": {
        "description": "Reporting API endpoint configuration",
        "missing_severity": "Info",
        "missing_impact": "Security violations not reported"
    },
}

DANGEROUS_HEADERS = {
    "Server": "Reveals server software and version — info disclosure",
    "X-Powered-By": "Reveals backend technology — info disclosure",
    "X-AspNet-Version": "Reveals ASP.NET version — info disclosure",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version — info disclosure",
}

def analyze_csp(csp_value: str) -> List[str]:
    issues = []
    if "unsafe-inline" in csp_value:
        issues.append("CSP contains 'unsafe-inline' — XSS protection weakened")
    if "unsafe-eval" in csp_value:
        issues.append("CSP contains 'unsafe-eval' — code injection possible")
    if "*" in csp_value:
        issues.append("CSP contains wildcard '*' — too permissive")
    return issues

def analyze_hsts(hsts_value: str) -> List[str]:
    issues = []
    if "max-age" in hsts_value:
        try:
            max_age = int(hsts_value.split("max-age=")[1].split(";")[0].strip())
            if max_age < 31536000:
                issues.append(f"HSTS max-age too short ({max_age}s) — recommend 1 year minimum")
        except Exception:
            pass
    if "includeSubDomains" not in hsts_value:
        issues.append("HSTS missing 'includeSubDomains' — subdomains not protected")
    if "preload" not in hsts_value:
        issues.append("HSTS missing 'preload' — not in browser preload list")
    return issues

def run_security_headers(target: str) -> Dict:
    url = f"https://{target}" if not target.startswith("http") else target
    
    present = {}
    missing = []
    warnings = []
    info_disclosure = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers = response.headers

        # Check security headers
        for header, meta in SECURITY_HEADERS.items():
            value = headers.get(header, "")
            if value:
                present[header] = value
                # Analyze specific headers
                if header == "Content-Security-Policy":
                    csp_issues = analyze_csp(value)
                    warnings.extend(csp_issues)
                elif header == "Strict-Transport-Security":
                    hsts_issues = analyze_hsts(value)
                    warnings.extend(hsts_issues)
            else:
                missing.append({
                    "header": header,
                    "severity": meta["missing_severity"],
                    "impact": meta["missing_impact"],
                    "description": meta["description"]
                })

        # Check dangerous headers
        for header, impact in DANGEROUS_HEADERS.items():
            value = headers.get(header, "")
            if value:
                info_disclosure.append({
                    "header": header,
                    "value": value,
                    "impact": impact,
                    "severity": "Medium"
                })

        # Calculate security score
        total = len(SECURITY_HEADERS)
        present_count = len(present)
        score = round((present_count / total) * 10, 1)

        # Grade
        if score >= 8:
            grade = "A"
        elif score >= 6:
            grade = "B"
        elif score >= 4:
            grade = "C"
        elif score >= 2:
            grade = "D"
        else:
            grade = "F"

        missing_high = [m for m in missing if m["severity"] == "High"]
        missing_medium = [m for m in missing if m["severity"] == "Medium"]

        return {
            "target": target,
            "status_code": response.status_code,
            "present_headers": present,
            "missing_headers": missing,
            "warnings": warnings,
            "info_disclosure": info_disclosure,
            "score": score,
            "grade": grade,
            "present_count": present_count,
            "total_checked": total,
            "high_severity_missing": len(missing_high),
            "medium_severity_missing": len(missing_medium),
        }

    except Exception as e:
        return {
            "target": target,
            "status_code": None,
            "present_headers": {},
            "missing_headers": [],
            "warnings": [],
            "info_disclosure": [],
            "score": 0,
            "grade": "F",
            "present_count": 0,
            "total_checked": len(SECURITY_HEADERS),
            "high_severity_missing": 0,
            "medium_severity_missing": 0,
            "error": str(e)
        }