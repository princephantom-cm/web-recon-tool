import aiohttp
import asyncio
import re
from typing import Dict, List
from urllib.parse import urljoin, urlparse

INTERESTING_PATHS = [
    # Admin & Control
    "admin", "administrator", "superadmin", "admin2", "admin3",
    "login", "signin", "signup", "register", "logout",
    "dashboard", "panel", "control", "manage", "mgmt",
    "cpanel", "whm", "plesk", "directadmin", "webmin",

    # API & Dev
    "api", "api2", "api3", "apiv1", "apiv2", "rest", "graphql",
    "swagger", "swagger-ui", "api-docs", "openapi", "redoc",
    "actuator", "actuator/env", "actuator/health", "actuator/trace",
    "debug", "trace", "info", "status", "health", "metrics",
    "console", "shell", "terminal", "exec", "cmd",

    # Config & Secrets
    "config", "configs", "configuration", "settings",
    ".env", ".env.local", ".env.prod", ".env.backup",
    ".git", ".git/config", ".svn", ".hg", ".DS_Store",
    "web.config", "app.config", "config.php", "config.xml",
    "database.yml", "database.php", "db.php", "db.xml",
    "secret", "secrets", "private", "internal",
    "credentials", "credential", "password", "passwd", "pass",
    "key", "keys", "token", "tokens", "apikey", "api_key",
    "access_token", "auth_token", "jwt", "oauth",

    # Files & Backup
    "backup", "backups", "bak", "old", "archive", "archives",
    "backup.zip", "backup.tar", "backup.sql", "db.sql",
    "dump.sql", "database.sql", "site.zip", "www.zip",
    "upload", "uploads", "files", "file", "documents",
    "download", "downloads", "export", "imports",
    "temp", "tmp", "cache", "logs", "log",

    # CMS & Framework
    "wp-admin", "wp-login", "wp-config", "wp-content",
    "wp-includes", "xmlrpc", "wp-json",
    "phpmyadmin", "pma", "mysql", "adminer",
    "joomla", "administrator", "components",
    "drupal", "sites/default", "user/login",
    "laravel", "storage", "bootstrap/cache",
    "django", "admin/login", "accounts/login",

    # Security & Pentest
    "shell.php", "c99.php", "r57.php", "webshell",
    "phpinfo", "phpinfo.php", "info.php", "test.php",
    "eval.php", "cmd.php", "exec.php",
    "server-status", "server-info", "nginx_status",
    "elmah.axd", "trace.axd", "webresource.axd",

    # Infrastructure
    "jenkins", "jenkins/login", "hudson",
    "gitlab", "github", "bitbucket",
    "jira", "confluence", "sonar", "nexus",
    "grafana", "kibana", "elasticsearch", "solr",
    "prometheus", "alertmanager", "zabbix", "nagios",
    "kubernetes", "k8s", "rancher", "portainer",
    "docker", "registry", "harbor",

    # Auth & SSO
    "auth", "authentication", "authorize", "oauth2",
    "sso", "saml", "openid", "identity", "idp",
    "forgot", "forgot-password", "reset", "reset-password",
    "verify", "verification", "activate", "activation",
    "2fa", "mfa", "otp", "totp",

    # Sensitive endpoints
    "cgi-bin", "cgi-bin/admin", "cgi-bin/login",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "security.txt", "humans.txt", "readme", "readme.md",
    "changelog", "license", "contributing", "readme.txt",
    "composer.json", "package.json", "yarn.lock",
    "requirements.txt", "Gemfile", "Pipfile",
    "Dockerfile", "docker-compose.yml", ".travis.yml",
    ".circleci", ".github", ".gitlab-ci.yml",
]


async def fetch_robots(session: aiohttp.ClientSession, base_url: str) -> Dict:
    url = f"{base_url}/robots.txt"
    result = {
        "found": False,
        "url": url,
        "disallowed": [],
        "allowed": [],
        "sitemaps": [],
        "interesting": []
    }

    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                result["found"] = True

                for line in text.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/" and path != "/*":
                            result["disallowed"].append(path)
                            for ip in INTERESTING_PATHS:
                                if ip in path.lower():
                                    result["interesting"].append(path)
                                    break
                    elif line.lower().startswith("allow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            result["allowed"].append(path)
                    elif line.lower().startswith("sitemap:"):
                        sitemap_url = line.split(":", 1)[1].strip()
                        if sitemap_url:
                            result["sitemaps"].append(sitemap_url)

    except Exception:
        pass

    return result


async def fetch_sitemap(session: aiohttp.ClientSession, sitemap_url: str) -> List[str]:
    urls = []
    try:
        async with session.get(sitemap_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
            if resp.status == 200:
                text = await resp.text()
                matches = re.findall(r'<loc>(.*?)</loc>', text)
                urls.extend(matches[:100])
    except Exception:
        pass
    return urls


async def fetch_default_sitemap(session: aiohttp.ClientSession, base_url: str) -> List[str]:
    default_sitemaps = [
        f"{base_url}/sitemap.xml",
        f"{base_url}/sitemap_index.xml",
        f"{base_url}/sitemap1.xml",
        f"{base_url}/wp-sitemap.xml",
    ]
    all_urls = []
    for sm_url in default_sitemaps:
        urls = await fetch_sitemap(session, sm_url)
        if urls:
            all_urls.extend(urls)
            break
    return all_urls


def extract_interesting_from_sitemap(urls: List[str]) -> List[str]:
    interesting = []
    for url in urls:
        path = urlparse(url).path.lower()
        for ip in INTERESTING_PATHS:
            if ip in path:
                interesting.append(url)
                break
    return interesting[:20]


async def run_robots_sitemap_async(target: str) -> Dict:
    base_url = f"https://{target}"
    base_url_http = f"http://{target}"

    async with aiohttp.ClientSession() as session:
        robots = await fetch_robots(session, base_url)
        if not robots["found"]:
            robots = await fetch_robots(session, base_url_http)

        sitemap_urls = []
        if robots["sitemaps"]:
            for sm in robots["sitemaps"][:3]:
                urls = await fetch_sitemap(session, sm)
                sitemap_urls.extend(urls)
        else:
            sitemap_urls = await fetch_default_sitemap(session, base_url)

    interesting_sitemap = extract_interesting_from_sitemap(sitemap_urls)

    return {
        "robots": robots,
        "sitemap_urls_count": len(sitemap_urls),
        "sitemap_sample": sitemap_urls[:10],
        "interesting_from_sitemap": interesting_sitemap,
        "all_interesting": list(set(robots["interesting"] + interesting_sitemap))
    }


def run_robots_sitemap(target: str) -> Dict:
    return asyncio.run(run_robots_sitemap_async(target))