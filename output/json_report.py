# output/json_report.py

import json
import os
from datetime import datetime
from typing import Dict


def generate_json_report(scan_data: Dict, output_dir: str = "reports") -> str:
    """
    Scan results ko JSON report mein save karta hai.
    
    Args:
        scan_data: Sab modules ka combined output
        output_dir: Report save karne ki directory
    
    Returns:
        Report file path
    """
    
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = scan_data.get("target", "unknown")
    filename = f"{domain}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    # Report structure
    report = {
        "meta": {
            "tool": "Web Recon Tool",
            "version": "1.0.0",
            "author": "github.com/yourusername",
            "timestamp": datetime.now().isoformat(),
            "target": domain
        },
        "summary": {
            "subdomains_found": scan_data.get("subdomains_count", 0),
            "live_hosts": scan_data.get("live_hosts_count", 0),
            "open_ports": scan_data.get("open_ports_count", 0),
            "cves_found": scan_data.get("cves_count", 0),
            "risk_priority": scan_data.get("risk_priority", "UNKNOWN"),
            "risk_score": scan_data.get("risk_score", 0)
        },
        "subdomains": {
            "passive_crtsh": scan_data.get("crtsh_subdomains", []),
            "active_dns_brute": scan_data.get("dns_brute_results", []),
            "wayback_urls": scan_data.get("wayback_urls", []),
            "wayback_interesting": scan_data.get("wayback_interesting", [])
        },
        "live_hosts": scan_data.get("live_hosts", []),
        "ports": scan_data.get("ports", []),
        "technologies": scan_data.get("technologies", []),
        "vulnerabilities": scan_data.get("vulnerabilities", []),
        "risk_assessment": {
            "score": scan_data.get("risk_score", 0),
            "priority": scan_data.get("risk_priority", "UNKNOWN"),
            "reasons": scan_data.get("risk_reasons", []),
            "next_steps": scan_data.get("next_steps", [])
        }
    }
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)
    
    return filepath


def load_json_report(filepath: str) -> Dict:
    """
    Saved JSON report load karta hai.
    
    Args:
        filepath: Report file path
    
    Returns:
        Report dict
    """
    
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"error": f"File not found: {filepath}"}
    except json.JSONDecodeError:
        return {"error": "Invalid JSON file"}