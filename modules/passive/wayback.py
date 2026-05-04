import aiohttp
import asyncio
from typing import List, Dict

INTERESTING_EXTENSIONS = [
    ".php", ".asp", ".aspx", ".jsp", ".env", ".config",
    ".xml", ".json", ".yaml", ".yml", ".bak", ".backup",
    ".sql", ".db", ".log", ".txt", ".zip", ".tar", ".gz",
    ".rar", ".7z", ".conf", ".ini", ".key", ".pem", ".crt",
    ".p12", ".pfx", ".jks", ".properties", ".cfg", ".settings",
    ".inc", ".old", ".orig", ".tmp", ".swp", ".DS_Store",
    ".htaccess", ".htpasswd", ".npmrc", ".dockerignore",
    ".gitignore", ".gitconfig", ".bash_history", ".ssh"
]

INTERESTING_PATHS = [
    "admin", "login", "wp-admin", "phpmyadmin", "dashboard",
    "api", "config", "backup", "upload", "uploads", "shell",
    "console", "manager", "administrator", "portal", "panel",
    "wp-login", "wp-config", "xmlrpc", "wp-json",
    "phpinfo", "info.php", "test.php", "debug",
    "swagger", "api-docs", "openapi", "graphql",
    "actuator", "env", "health", "metrics", "trace",
    "jenkins", "gitlab", "jira", "confluence",
    "setup", "install", "setup.php", "install.php",
    "register", "signup", "forgot", "reset", "password",
    "secret", "secrets", "private", "internal",
    "cgi-bin", "scripts", "bin", "exe",
    "database", "db", "mysql", "phpmyadmin",
    "cpanel", "whm", "webmail", "plesk",
    "remote", "ssh", "sftp", "ftp",
    "static", "assets", "files", "downloads",
    "old", "bak", "backup", "archive",
    "test", "dev", "staging", "beta",
    "server-status", "server-info",
    ".git", ".svn", ".hg", ".env",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "security.txt", "humans.txt", "readme",
    "changelog", "license", "contributing"
]

SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "token", "api_key",
    "apikey", "auth", "credential", "private", "key",
    "access_token", "refresh_token", "client_secret",
    "aws_secret", "aws_key", "s3_key", "db_pass",
    "database_url", "connection_string", "jdbc",
    "smtp_pass", "mail_pass", "ftp_pass", "ssh_key"
]

async def fetch_wayback_urls(domain: str, session: aiohttp.ClientSession) -> List[str]:
    """Fetch URLs from Wayback Machine CDX API"""
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            data = await resp.json()
            if not data or len(data) < 2:
                return []
            return [row[0] for row in data[1:]]
    except Exception:
        return []

async def fetch_alienvault_urls(domain: str, session: aiohttp.ClientSession) -> List[str]:
    """Fetch URLs from AlienVault OTX passive DNS"""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=200"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json()
            urls = []
            for entry in data.get("url_list", []):
                u = entry.get("url", "")
                if u:
                    urls.append(u)
            return urls
    except Exception:
        return []

async def fetch_commoncrawl_urls(domain: str, session: aiohttp.ClientSession) -> List[str]:
    """Fetch URLs from Common Crawl index"""
    url = f"https://index.commoncrawl.org/CC-MAIN-2023-50-index?url=*.{domain}/*&output=json&limit=200"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            text = await resp.text()
            urls = []
            for line in text.strip().split("\n"):
                try:
                    import json
                    obj = json.loads(line)
                    u = obj.get("url", "")
                    if u:
                        urls.append(u)
                except Exception:
                    continue
            return urls
    except Exception:
        return []

def categorize_url(url: str) -> str:
    url_lower = url.lower()
    
    for kw in SENSITIVE_KEYWORDS:
        if kw in url_lower:
            return "sensitive"
    
    for ext in [".env", ".git", ".sql", ".bak", ".backup", ".key", ".pem", ".config"]:
        if ext in url_lower:
            return "sensitive"
    
    for path in ["admin", "phpmyadmin", "wp-admin", "cpanel", "shell", "console"]:
        if f"/{path}" in url_lower:
            return "admin"
    
    for ext in [".php", ".asp", ".aspx", ".jsp"]:
        if ext in url_lower:
            return "endpoint"
    
    for path in ["api", "swagger", "graphql", "openapi", "actuator"]:
        if f"/{path}" in url_lower:
            return "api"
    
    for ext in INTERESTING_EXTENSIONS:
        if ext in url_lower:
            return "file"
    
    for path in INTERESTING_PATHS:
        if f"/{path}" in url_lower:
            return "interesting"
    
    return "normal"

def filter_interesting_urls(urls: List[str]) -> Dict:
    sensitive = []
    admin = []
    api_endpoints = []
    interesting_files = []
    interesting_paths = []
    
    seen = set()
    
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        
        category = categorize_url(url)
        
        if category == "sensitive" and len(sensitive) < 20:
            sensitive.append(url)
        elif category == "admin" and len(admin) < 15:
            admin.append(url)
        elif category == "api" and len(api_endpoints) < 15:
            api_endpoints.append(url)
        elif category == "file" and len(interesting_files) < 15:
            interesting_files.append(url)
        elif category == "interesting" and len(interesting_paths) < 15:
            interesting_paths.append(url)
    
    all_interesting = sensitive + admin + api_endpoints + interesting_files + interesting_paths
    
    return {
        "sensitive": sensitive,
        "admin": admin,
        "api_endpoints": api_endpoints,
        "interesting_files": interesting_files,
        "interesting_paths": interesting_paths,
        "all": all_interesting[:50]
    }

async def run_all_sources(domain: str) -> Dict:
    async with aiohttp.ClientSession() as session:
        wayback, alienvault, commoncrawl = await asyncio.gather(
            fetch_wayback_urls(domain, session),
            fetch_alienvault_urls(domain, session),
            fetch_commoncrawl_urls(domain, session)
        )
    
    all_urls = list(set(wayback + alienvault + commoncrawl))
    categorized = filter_interesting_urls(all_urls)
    
    return {
        "total_fetched": len(all_urls),
        "sources": {
            "wayback": len(wayback),
            "alienvault": len(alienvault),
            "commoncrawl": len(commoncrawl)
        },
        **categorized
    }

def run_wayback(domain: str) -> Dict:
    return asyncio.run(run_all_sources(domain))