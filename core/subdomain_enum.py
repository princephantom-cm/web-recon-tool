import asyncio
import aiohttp
import re
from typing import List, Dict

WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "blog", "shop", "secure", "login",
    "app", "mobile", "cdn", "static", "media", "smtp", "pop", "imap",
    "ns1", "ns2", "mx", "autodiscover", "webmail", "cpanel", "whm",
    "beta", "alpha", "demo", "old", "new", "v1", "v2", "v3",
    "internal", "intranet", "corp", "office", "support", "help",
    "status", "monitor", "dashboard", "panel", "manage", "mgmt",
    "git", "gitlab", "github", "jira", "confluence", "wiki",
    "jenkins", "ci", "cd", "build", "deploy", "prod", "production",
    "sandbox", "uat", "qa", "stage", "preprod", "backup",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "ssh", "sftp", "storage", "files", "assets", "images",
    "proxy", "gateway", "lb", "loadbalancer", "waf", "firewall",
    "auth", "sso", "oauth", "id", "identity", "accounts",
    "pay", "payment", "billing", "invoice", "checkout",
    "metrics", "grafana", "kibana", "elastic", "logs",
    "api2", "api3", "apiv1", "apiv2", "rest", "graphql", "grpc",
    "web", "web1", "web2", "www1", "www2", "www3",
    "mail2", "mail3", "smtp2", "mx1", "mx2", "mx3",
    "dev1", "dev2", "dev3", "test1", "test2", "test3",
    "admin2", "administrator", "superadmin", "root",
    "secure2", "security", "ssl", "tls", "vpn2", "vpn3",
    "remote2", "rdp", "citrix", "terminal",
    "cloud", "aws", "azure", "gcp", "s3", "bucket",
    "upload", "download", "transfer", "share", "drive",
    "video", "stream", "live", "media2", "audio",
    "news", "press", "events", "careers", "jobs", "hr",
    "legal", "privacy", "terms", "compliance", "audit",
    "finance", "accounting", "erp", "crm", "sales",
    "marketing", "analytics", "tracking", "pixel",
    "exchange", "owa", "outlook", "calendar",
    "forum", "community", "discuss", "chat", "slack",
    "docs", "documentation", "help2", "kb", "knowledge",
    "ticket", "tickets", "service", "servicedesk", "itsm",
    "nagios", "zabbix", "prometheus", "alertmanager",
    "vault", "secrets", "config", "configs", "settings",
    "registry", "docker", "k8s", "kubernetes", "rancher",
    "sonar", "sonarqube", "nexus", "artifactory",
    "smtp3", "relay", "bounce", "notify", "notification",
    "report", "reports", "export", "import", "sync",
    "mobile2", "android", "ios", "app2", "apps",
    "token", "key", "keys", "cert", "certs", "pki",
    "node", "node1", "node2", "server", "server1", "server2",
    "host", "host1", "host2", "box", "machine",
    "office365", "teams", "zoom", "meet", "webex",
    "partner", "partners", "vendor", "vendors", "supplier",
    "customer", "client", "clients", "user", "users",
    "public", "private", "external", "internal2",
    "test4", "demo2", "preview", "review", "staging2",
    "search", "index", "home", "landing", "redirect",
    "error", "errors", "debug", "trace", "health", "ping",
    "ftp2", "ftp3", "ns3", "ns4", "ns5", "dns", "dns1", "dns2",
    "pop3", "imap2", "imap3", "smtp4", "mail4", "mail5",
    "vpn1", "vpn4", "vpn5", "remote3", "remote4",
    "api4", "api5", "apiv3", "apiv4", "v4", "v5",
    "www4", "www5", "web3", "web4", "web5",
    "dev4", "dev5", "test5", "test6", "qa2", "qa3",
    "staging3", "staging4", "preprod2", "uat2",
    "prod2", "prod3", "production2", "live2",
    "db2", "db3", "database2", "mysql2", "postgres2",
    "redis2", "mongo2", "elastic2", "kafka", "rabbitmq",
    "zookeeper", "consul", "etcd", "vault2",
    "jenkins2", "ci2", "cd2", "build2", "deploy2",
    "gitlab2", "github2", "bitbucket", "svn",
    "jira2", "confluence2", "wiki2", "docs2",
    "grafana2", "kibana2", "prometheus2", "nagios2",
    "admin3", "admin4", "panel2", "panel3", "dashboard2",
    "manage2", "mgmt2", "console2", "control",
    "cpanel2", "whm2", "plesk", "directadmin",
    "webmail2", "roundcube", "squirrelmail",
    "shop2", "store", "ecommerce", "cart", "checkout2",
    "pay2", "payment2", "billing2", "invoice2",
    "crm2", "erp2", "hrm", "hris", "payroll",
    "helpdesk", "servicedesk2", "itsm2", "cmdb",
    "monitoring", "alerting", "logging", "tracing",
    "waf2", "ids", "ips", "firewall2", "proxy2",
    "gateway2", "lb2", "haproxy", "nginx", "apache",
    "tomcat", "jboss", "wildfly", "websphere",
    "oracle", "mssql", "mariadb", "cassandra", "couchdb",
    "memcached", "elasticsearch", "solr", "sphinx",
    "backup2", "backup3", "dr", "bcp", "failover",
    "primary", "secondary", "replica", "master", "slave",
    "edge", "edge2", "cdn2", "cdn3",
    "assets2", "static2", "images2", "downloads2",
    "archive", "archives", "legacy", "classic",
    "sandbox2", "playground", "lab", "labs", "research",
    "poc", "prototype", "experimental",
    "training", "learn", "education",
    "partner2", "reseller", "affiliate",
    "us", "eu", "ap", "uk", "de", "fr", "in",
    "us-east", "us-west", "eu-west", "ap-south",
    "zone1", "zone2", "az1", "az2", "az3",
    "jump", "bastion", "jumphost", "jumpbox",
    "soc", "csirt", "infosec",
    "ldap", "ad", "radius",
    "saml", "openid", "keycloak", "okta",
    "splunk", "datadog", "newrelic",
    "ansible", "terraform",
]


# ─────────────────────────────────────────────
# PASSIVE: crt.sh
# ─────────────────────────────────────────────
async def query_crtsh(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
            data = await resp.json(content_type=None)
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if domain in sub and "*" not in sub:
                        subdomains.add(sub)
            return list(subdomains)
    except Exception:
        return []


# ─────────────────────────────────────────────
# PASSIVE: HackerTarget
# ─────────────────────────────────────────────
async def query_hackertarget(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            text = await resp.text()
            subdomains = set()
            for line in text.strip().split("\n"):
                if "," in line:
                    sub = line.split(",")[0].strip()
                    if domain in sub and not sub.startswith("API"):
                        subdomains.add(sub)
            return list(subdomains)
    except Exception:
        return []


# ─────────────────────────────────────────────
# PASSIVE: RapidDNS
# ─────────────────────────────────────────────
async def query_rapiddns(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Mozilla/5.0"}
        ) as resp:
            text = await resp.text()
            pattern = rf'[\w\-\.]+\.{re.escape(domain)}'
            matches = re.findall(pattern, text)
            return list({m.strip() for m in matches if "*" not in m})
    except Exception:
        return []


# ─────────────────────────────────────────────
# PASSIVE: AlienVault OTX
# ─────────────────────────────────────────────
async def query_alienvault(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json(content_type=None)
            subdomains = set()
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "").strip()
                if domain in hostname and "*" not in hostname:
                    subdomains.add(hostname)
            return list(subdomains)
    except Exception:
        return []


# ─────────────────────────────────────────────
# PASSIVE: BufferOver (DNS aggregator)
# ─────────────────────────────────────────────
async def query_bufferover(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            data = await resp.json(content_type=None)
            subdomains = set()
            for record in data.get("FDNS_A", []) + data.get("RDNS", []):
                parts = record.split(",")
                for part in parts:
                    part = part.strip()
                    if domain in part and "*" not in part:
                        subdomains.add(part)
            return list(subdomains)
    except Exception:
        return []


# ─────────────────────────────────────────────
# PASSIVE: URLScan.io
# ─────────────────────────────────────────────
async def query_urlscan(domain: str, session: aiohttp.ClientSession) -> List[str]:
    url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100"
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Mozilla/5.0"}
        ) as resp:
            data = await resp.json(content_type=None)
            subdomains = set()
            for result in data.get("results", []):
                page = result.get("page", {})
                hostname = page.get("domain", "")
                if domain in hostname and "*" not in hostname:
                    subdomains.add(hostname.strip())
            return list(subdomains)
    except Exception:
        return []


# ─────────────────────────────────────────────
# ACTIVE: DNS Resolution Brute Force
# ─────────────────────────────────────────────
async def resolve_subdomain(subdomain: str, semaphore: asyncio.Semaphore) -> str | None:
    async with semaphore:
        try:
            loop = asyncio.get_event_loop()
            # getaddrinfo does actual DNS resolution — much more reliable than TCP connect
            result = await asyncio.wait_for(
                loop.getaddrinfo(subdomain, None),
                timeout=3.0
            )
            if result:
                return subdomain
        except Exception:
            return None
    return None


async def brute_force_subdomains(domain: str) -> List[str]:
    # Semaphore limits concurrent DNS queries — avoids overwhelming resolver
    semaphore = asyncio.Semaphore(100)
    tasks = [
        resolve_subdomain(f"{word}.{domain}", semaphore)
        for word in WORDLIST
    ]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


# ─────────────────────────────────────────────
# MAIN ENUMERATION
# ─────────────────────────────────────────────
async def enumerate_subdomains(domain: str) -> Dict:
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        (
            crtsh,
            hackertarget,
            rapiddns,
            alienvault,
            bufferover,
            urlscan
        ) = await asyncio.gather(
            query_crtsh(domain, session),
            query_hackertarget(domain, session),
            query_rapiddns(domain, session),
            query_alienvault(domain, session),
            query_bufferover(domain, session),
            query_urlscan(domain, session),
        )

    # Brute force runs separately (DNS, not HTTP)
    active = await brute_force_subdomains(domain)

    passive = list(set(
        crtsh + hackertarget + rapiddns +
        alienvault + bufferover + urlscan
    ))
    all_subs = list(set(passive + active))

    return {
        "domain":  domain,
        "passive": passive,
        "active":  active,
        "total":   all_subs,
        "sources": {
            "crtsh":        len(crtsh),
            "hackertarget": len(hackertarget),
            "rapiddns":     len(rapiddns),
            "alienvault":   len(alienvault),
            "bufferover":   len(bufferover),
            "urlscan":      len(urlscan),
            "brute_force":  len(active),
        }
    }


def run_subdomain_enum(domain: str) -> Dict:
    return asyncio.run(enumerate_subdomains(domain))