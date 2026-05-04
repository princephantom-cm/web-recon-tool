# modules/passive/crt_sh.py

import requests
import json
from typing import List, Dict


def fetch_crtsh(domain: str, timeout: int = 30) -> Dict:
    """
    crt.sh Certificate Transparency logs se subdomains fetch karta hai.
    """
    
    # Updated URL format
    url = f"https://crt.sh/?q={domain}&output=json"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        data = response.json()
        
        subdomains = set()
        
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lower()
                if sub and not sub.startswith("*") and domain in sub:
                    subdomains.add(sub)
        
        subdomains = sorted(list(subdomains))
        
        return {
            "domain": domain,
            "source": "crt.sh",
            "subdomains": subdomains,
            "count": len(subdomains)
        }
        
    except requests.Timeout:
        return {"domain": domain, "source": "crt.sh", "subdomains": [], "count": 0, "error": "Timeout"}
    except requests.ConnectionError:
        return {"domain": domain, "source": "crt.sh", "subdomains": [], "count": 0, "error": "Connection Error"}
    except json.JSONDecodeError:
        return {"domain": domain, "source": "crt.sh", "subdomains": [], "count": 0, "error": "Invalid JSON"}
    except Exception as e:
        return {"domain": domain, "source": "crt.sh", "subdomains": [], "count": 0, "error": str(e)}