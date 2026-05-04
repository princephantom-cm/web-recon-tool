# modules/active/dns_brute.py

import asyncio
import dns.resolver
from typing import List, Dict


async def brute_single(subdomain: str, domain: str, timeout: int = 3) -> Dict:
    """Single subdomain ko DNS resolve karta hai."""
    
    full_domain = f"{subdomain}.{domain}"
    
    loop = asyncio.get_event_loop()
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        result = await loop.run_in_executor(
            None,
            lambda: resolver.resolve(full_domain, 'A')
        )
        
        ips = [str(r) for r in result]
        
        return {
            "subdomain": full_domain,
            "resolved": True,
            "ips": ips,
            "record_type": "A"
        }
        
    except dns.resolver.NXDOMAIN:
        return {"subdomain": full_domain, "resolved": False, "ips": [], "record_type": None}
    except dns.resolver.NoAnswer:
        return {"subdomain": full_domain, "resolved": False, "ips": [], "record_type": None}
    except dns.resolver.Timeout:
        return {"subdomain": full_domain, "resolved": False, "ips": [], "record_type": None}
    except Exception:
        return {"subdomain": full_domain, "resolved": False, "ips": [], "record_type": None}


async def brute_all(domain: str, wordlist: List[str], concurrency: int = 20, timeout: int = 3) -> Dict:
    """
    Saare subdomains ko concurrently DNS brute force karta hai.
    
    Args:
        domain: Target domain (e.g. hackthebox.com)
        wordlist: List of subdomains to try
        concurrency: Concurrent DNS requests
        timeout: Per request timeout
    
    Returns:
        Dict with resolved/unresolved + stats
    """
    
    if not wordlist:
        return {
            "resolved": [],
            "unresolved": [],
            "total": 0,
            "resolved_count": 0
        }
    
    semaphore = asyncio.Semaphore(concurrency)
    
    async def bounded_brute(subdomain):
        async with semaphore:
            return await brute_single(subdomain, domain, timeout)
    
    tasks = [bounded_brute(sub) for sub in wordlist]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    resolved = []
    unresolved = []
    
    for result in results:
        if isinstance(result, Exception):
            continue
        if result.get("resolved"):
            resolved.append(result)
        else:
            unresolved.append(result)
    
    return {
        "resolved": resolved,
        "unresolved": unresolved,
        "total": len(wordlist),
        "resolved_count": len(resolved)
    }


def dns_brute_force(domain: str, wordlist: List[str] = None, concurrency: int = 20, timeout: int = 3) -> Dict:
    """
    Sync wrapper — main.py se easily call ho sake.
    
    Args:
        domain: Target domain
        wordlist: Custom wordlist (default wordlist use hogi agar None)
        concurrency: Concurrent requests
        timeout: Timeout per request
    
    Returns:
        Brute force results dict
    """
    
    # Default wordlist
    default_wordlist = [
        "www", "mail", "ftp", "admin", "api", "app", "dev", "staging",
        "test", "beta", "portal", "dashboard", "cdn", "static", "assets",
        "blog", "shop", "store", "secure", "vpn", "remote", "git",
        "gitlab", "github", "jenkins", "jira", "confluence", "support",
        "help", "docs", "status", "monitor", "internal", "intranet",
        "mx", "smtp", "pop", "imap", "webmail", "ns1", "ns2", "dns",
        "auth", "login", "sso", "oauth", "api-v1", "api-v2", "backend",
        "frontend", "mobile", "m", "wap", "old", "new", "sandbox"
    ]
    
    if wordlist is None:
        wordlist = default_wordlist
    
    return asyncio.run(brute_all(domain, wordlist, concurrency, timeout))