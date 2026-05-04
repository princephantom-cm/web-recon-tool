import aiohttp
import asyncio
import re
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

INTERESTING_PATTERNS = [
    r'/api/[v\d]*/[\w\-/\.]*',
    r'/auth/[\w\-/\.]*',
    r'/login[\w\-/\.]*',
    r'/admin[\w\-/\.]*',
    r'/dashboard[\w\-/\.]*',
    r'/user/[\w\-/\.]*',
    r'/account[\w\-/\.]*',
    r'/payment[\w\-/\.]*',
    r'/checkout[\w\-/\.]*',
    r'/config[\w\-/\.]*',
    r'/backup[\w\-/\.]*',
    r'/upload[\w\-/\.]*',
    r'/download[\w\-/\.]*',
    r'/export[\w\-/\.]*',
    r'/import[\w\-/\.]*',
    r'/debug[\w\-/\.]*',
    r'/test[\w\-/\.]*',
    r'/dev[\w\-/\.]*',
    r'/internal[\w\-/\.]*',
    r'/private[\w\-/\.]*',
    r'/secret[\w\-/\.]*',
    r'/token[\w\-/\.]*',
    r'/oauth[\w\-/\.]*',
    r'/reset[\w\-/\.]*',
    r'/forgot[\w\-/\.]*',
    r'/v\d+/[\w\-/\.]*',
    r'/graphql[\w\-/\.]*',
    r'/swagger[\w\-/\.]*',
    r'/docs[\w\-/\.]*',
]

INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".env",
    ".config", ".xml", ".json", ".sql", ".bak",
    ".log", ".txt", ".zip", ".tar", ".gz"
]

BLOCKED_DOMAINS = [
    "facebook.com", "twitter.com", "linkedin.com",
    "google.com", "instagram.com", "youtube.com",
    "tiktok.com", "reddit.com", "wikipedia.org"
]


def is_interesting(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(re.search(p, path) for p in INTERESTING_PATTERNS) or \
           any(path.endswith(ext) for ext in INTERESTING_EXTENSIONS)


def classify_url(url: str) -> str:
    url_lower = url.lower()

    if any(x in url_lower for x in [
        "/admin", "/login", "/auth", "/shell", "/config",
        "/backup", "/upload", "/phpmyadmin", "/wp-admin",
        "/console", "/secret", "/token", "/password",
        "/wp-login", "/xmlrpc", "/env", "/.git"
    ]):
        return "HIGH"

    elif any(x in url_lower for x in [
        "/api", "/v1/", "/v2/", "/v3/", "/graphql", "/swagger",
        "/dashboard", "/profile", "/settings", "/data",
        "/export", "/import", "/reset", "/forgot", "/user",
        "/account", "/payment", "/checkout"
    ]):
        return "MEDIUM"

    return "LOW"


def extract_links(html: str, base_url: str, domain: str) -> Set[str]:
    links = set()

    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
        r'url\(["\']?([^"\')\s]+)["\']?\)',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    ]

    for pattern in patterns:
        for match in re.findall(pattern, html, re.IGNORECASE):
            if match.startswith("http"):
                if domain in match:
                    links.add(match)
            elif match.startswith("/"):
                links.add(urljoin(base_url, match))
            elif not match.startswith(("#", "javascript:", "mailto:", "tel:")):
                links.add(urljoin(base_url, match))

    return links


async def crawl_page(session, url, domain, visited, found_urls, interesting_urls, depth=0, max_depth=2):
    if url in visited or depth > max_depth:
        return

    visited.add(url)

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
            if resp.status == 200:
                content_type = resp.headers.get("Content-Type", "")

                if "html" in content_type or "javascript" in content_type:
                    html = await resp.text(errors="ignore")
                    links = extract_links(html, url, domain)

                    for link in links:
                        if link not in found_urls:
                            found_urls.add(link)

                            if is_interesting(link):
                                interesting_urls.add(link)

                        if depth < max_depth:
                            parsed = urlparse(link)

                            if parsed.netloc.endswith(domain) and \
                               not any(bd in parsed.netloc for bd in BLOCKED_DOMAINS):
                                await crawl_page(
                                    session, link, domain,
                                    visited, found_urls, interesting_urls,
                                    depth + 1, max_depth
                                )

    except Exception:
        return


async def run_crawler_async(target: str, max_depth: int = 2) -> Dict:
    domain = target
    base_urls = [f"https://{target}", f"http://{target}"]

    visited = set()
    found_urls = set()
    interesting_urls = set()

    connector = aiohttp.TCPConnector(limit=20, ssl=False)

    async with aiohttp.ClientSession(connector=connector) as session:
        for base_url in base_urls:
            await crawl_page(
                session, base_url, domain,
                visited, found_urls, interesting_urls,
                0, max_depth
            )
            if found_urls:
                break

    interesting_list = list(interesting_urls)

    priority_map = {u: classify_url(u) for u in interesting_list}

    high   = sorted([u for u, p in priority_map.items() if p == "HIGH"])
    medium = sorted([u for u, p in priority_map.items() if p == "MEDIUM"])
    low    = sorted([u for u, p in priority_map.items() if p == "LOW"])

    api_endpoints   = [u for u in interesting_list if "/api/" in u or "/v1/" in u or "/v2/" in u]
    auth_endpoints  = [u for u in interesting_list if any(x in u for x in ["/login", "/auth", "/oauth", "/reset", "/forgot"])]
    admin_endpoints = [u for u in interesting_list if any(x in u for x in ["/admin", "/dashboard", "/panel", "/console"])]
    sensitive_files = [u for u in interesting_list if any(u.endswith(ext) for ext in INTERESTING_EXTENSIONS)]

    return {
        "total_urls_found":   len(found_urls),
        "total_interesting":  len(interesting_list),

        "api_endpoints":   list(set(api_endpoints))[:15],
        "auth_endpoints":  list(set(auth_endpoints))[:15],
        "admin_endpoints": list(set(admin_endpoints))[:15],
        "sensitive_files": list(set(sensitive_files))[:15],

        "all_interesting": interesting_list[:50],

        "prioritized": {
            "high":   high[:10],
            "medium": medium[:10],
            "low":    low[:10],
        }
    }


def run_crawler(target: str, max_depth: int = 2) -> Dict:
    return asyncio.run(run_crawler_async(target, max_depth))
