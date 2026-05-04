import asyncio
import aiohttp
from typing import List, Dict

async def probe_host(session: aiohttp.ClientSession, subdomain: str) -> Dict:
    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=8),
                allow_redirects=True,
                ssl=False
            ) as resp:
                return {
                    "subdomain": subdomain,
                    "url": str(resp.url),
                    "status_code": resp.status,
                    "alive": True,
                    "scheme": scheme,
                    "server": resp.headers.get("Server", ""),
                    "title": await extract_title(resp),
                }
        except Exception:
            continue

    return {
        "subdomain": subdomain,
        "url": "",
        "status_code": None,
        "alive": False,
        "scheme": "",
        "server": "",
        "title": ""
    }

async def extract_title(response) -> str:
    try:
        text = await response.text(errors="ignore")
        start = text.lower().find("<title>")
        end = text.lower().find("</title>")
        if start != -1 and end != -1:
            return text[start+7:end].strip()[:100]
    except Exception:
        pass
    return ""

async def probe_all(subdomains: List[str]) -> List[Dict]:
    alive = []
    connector = aiohttp.TCPConnector(limit=50, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [probe_host(session, sub) for sub in subdomains]
        results = await asyncio.gather(*tasks)
        alive = [r for r in results if r["alive"]]
    return alive

def run_http_probe(subdomains: List[str]) -> Dict:
    alive_hosts = asyncio.run(probe_all(subdomains))
    return {
        "total_probed": len(subdomains),
        "alive_count": len(alive_hosts),
        "alive_hosts": alive_hosts
    }
    