import aiohttp
import asyncio
import re
from typing import Dict, List

# Regex patterns for sensitive data
PATTERNS = {
    "api_endpoints": [
        r'["\'](/api/[v\d]*[/\w\-\.]*)["\']',
        r'["\'](/v\d+/[\w\-/\.]*)["\']',
        r'fetch\(["\']([/\w\-\.]+)["\']',
        r'axios\.[a-z]+\(["\']([/\w\-\.]+)["\']',
        r'url:\s*["\']([/\w\-\.]+)["\']',
    ],
    "aws_keys": [
        r'AKIA[0-9A-Z]{16}',
        r'aws_access_key_id\s*=\s*["\']([A-Z0-9]{20})["\']',
        r'aws_secret_access_key\s*=\s*["\']([A-Za-z0-9/+=]{40})["\']',
    ],
    "api_keys": [
        r'api[_-]?key["\s]*[:=]["\s]*([A-Za-z0-9\-_]{20,})',
        r'apikey["\s]*[:=]["\s]*([A-Za-z0-9\-_]{20,})',
        r'access[_-]?token["\s]*[:=]["\s]*([A-Za-z0-9\-_\.]{20,})',
        r'auth[_-]?token["\s]*[:=]["\s]*([A-Za-z0-9\-_\.]{20,})',
        r'client[_-]?secret["\s]*[:=]["\s]*([A-Za-z0-9\-_]{20,})',
    ],
    "jwt_tokens": [
        r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*',
    ],
    "google_keys": [
        r'AIza[0-9A-Za-z\-_]{35}',
        r'["\']G-[A-Z0-9]{10}["\']',
    ],
    "private_keys": [
        r'-----BEGIN [A-Z]+ PRIVATE KEY-----',
        r'-----BEGIN RSA PRIVATE KEY-----',
    ],
    "passwords": [
        r'password["\s]*[:=]["\s]*["\']([^"\']{8,})["\']',
        r'passwd["\s]*[:=]["\s]*["\']([^"\']{8,})["\']',
        r'pwd["\s]*[:=]["\s]*["\']([^"\']{8,})["\']',
    ],
    "emails": [
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    ],
    "internal_urls": [
        r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"\']*',
        r'https?://[a-z0-9\-]+\.internal[^\s"\']*',
        r'https?://[a-z0-9\-]+\.local[^\s"\']*',
    ],
    "s3_buckets": [
        r's3\.amazonaws\.com/([a-z0-9\-\.]+)',
        r'([a-z0-9\-\.]+)\.s3\.amazonaws\.com',
        r's3://([a-z0-9\-\.]+)',
    ],
}

SEVERITY_MAP = {
    "aws_keys": "Critical",
    "private_keys": "Critical",
    "jwt_tokens": "High",
    "api_keys": "High",
    "google_keys": "High",
    "passwords": "High",
    "s3_buckets": "Medium",
    "internal_urls": "Medium",
    "api_endpoints": "Info",
    "emails": "Info",
}

async def fetch_js_files(session: aiohttp.ClientSession, base_url: str) -> List[str]:
    """Fetch all JS file URLs from the main page"""
    js_files = []
    try:
        async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            text = await resp.text(errors="ignore")
            # Find JS files
            patterns = [
                r'src=["\']([^"\']*\.js[^"\']*)["\']',
                r'src=["\']([^"\']*\.js)["\']',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, text)
                for match in matches:
                    if match.startswith("http"):
                        js_files.append(match)
                    elif match.startswith("/"):
                        js_files.append(f"{base_url}{match}")
                    else:
                        js_files.append(f"{base_url}/{match}")
    except Exception:
        pass
    return list(set(js_files))[:20]

async def analyze_js_file(session: aiohttp.ClientSession, js_url: str) -> Dict:
    """Analyze a single JS file for sensitive data"""
    findings = {}
    try:
        async with session.get(js_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                content = await resp.text(errors="ignore")
                for category, patterns in PATTERNS.items():
                    matches = set()
                    for pattern in patterns:
                        found = re.findall(pattern, content, re.IGNORECASE)
                        for f in found:
                            if isinstance(f, tuple):
                                matches.update(f)
                            else:
                                matches.add(f)
                    if matches:
                        findings[category] = list(matches)[:5]
    except Exception:
        pass
    return {"url": js_url, "findings": findings}

async def run_js_analysis_async(target: str) -> Dict:
    base_url = f"https://{target}"
    all_findings = {cat: [] for cat in PATTERNS.keys()}
    sensitive_findings = []
    js_files_analyzed = []

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        js_files = await fetch_js_files(session, base_url)
        if not js_files:
            base_url = f"http://{target}"
            js_files = await fetch_js_files(session, base_url)

        tasks = [analyze_js_file(session, js_url) for js_url in js_files]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result["findings"]:
                js_files_analyzed.append(result["url"])
                for category, matches in result["findings"].items():
                    all_findings[category].extend(matches)
                    severity = SEVERITY_MAP.get(category, "Info")
                    if severity in ["Critical", "High"]:
                        for match in matches:
                            sensitive_findings.append({
                                "type": category,
                                "value": match[:100],
                                "severity": severity,
                                "source": result["url"]
                            })

    # Deduplicate
    for cat in all_findings:
        all_findings[cat] = list(set(all_findings[cat]))[:10]

    return {
        "js_files_found": len(js_files),
        "js_files_analyzed": len(js_files_analyzed),
        "sensitive_findings": sensitive_findings,
        "api_endpoints": all_findings.get("api_endpoints", []),
        "emails": all_findings.get("emails", []),
        "internal_urls": all_findings.get("internal_urls", []),
        "s3_buckets": all_findings.get("s3_buckets", []),
        "all_findings": {k: v for k, v in all_findings.items() if v},
    }

def run_js_analyzer(target: str) -> Dict:
    return asyncio.run(run_js_analysis_async(target))