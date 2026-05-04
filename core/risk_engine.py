from typing import Dict, List

SEVERITY_WEIGHTS = {
    "Critical": 10.0,
    "High": 7.0,
    "Medium": 4.0,
    "Low": 2.0,
    "Info": 0.0
}

RISKY_PORTS = {
    21: ("FTP", "High"),
    22: ("SSH", "Medium"),
    23: ("Telnet", "Critical"),
    25: ("SMTP", "Medium"),
    445: ("SMB", "High"),
    3306: ("MySQL", "High"),
    3389: ("RDP", "High"),
    5900: ("VNC", "High"),
    6379: ("Redis", "Critical"),
    27017: ("MongoDB", "Critical"),
}


# ─────────────────────────────────────────────
# PORT ANALYSIS
# ─────────────────────────────────────────────
def analyze_ports(port_data: List[Dict]) -> List[Dict]:
    findings = []
    for p in port_data:
        port_num = p.get("port")
        if port_num in RISKY_PORTS:
            service, severity = RISKY_PORTS[port_num]
            findings.append({
                "type": "port",
                "port": port_num,
                "service": service,
                "severity": severity,
                "description": f"Port {port_num} ({service}) exposed — direct attack vector",
                "weight": SEVERITY_WEIGHTS[severity]
            })
    return findings


# ─────────────────────────────────────────────
# WAYBACK ANALYSIS
# ─────────────────────────────────────────────
def analyze_wayback(wayback_data: Dict) -> List[Dict]:
    findings = []

    sensitive_count = len(wayback_data.get("sensitive", []))
    admin_count = len(wayback_data.get("admin", []))
    api_count = len(wayback_data.get("api_endpoints", []))

    if sensitive_count >= 10:
        findings.append({
            "type": "wayback",
            "severity": "Medium",
            "description": f"{sensitive_count} sensitive URLs found in Wayback Machine",
            "weight": SEVERITY_WEIGHTS["Medium"]
        })
    elif sensitive_count >= 3:
        findings.append({
            "type": "wayback",
            "severity": "Low",
            "description": f"{sensitive_count} sensitive URLs found in Wayback Machine",
            "weight": SEVERITY_WEIGHTS["Low"]
        })

    if admin_count >= 5:
        findings.append({
            "type": "wayback",
            "severity": "Medium",
            "description": f"{admin_count} admin panel URLs found in history",
            "weight": SEVERITY_WEIGHTS["Medium"]
        })
    elif admin_count >= 2:
        findings.append({
            "type": "wayback",
            "severity": "Low",
            "description": f"{admin_count} admin panel URLs found in history",
            "weight": SEVERITY_WEIGHTS["Low"]
        })

    if api_count >= 5:
        findings.append({
            "type": "wayback",
            "severity": "Low",
            "description": f"{api_count} API endpoints found in history — test for IDOR",
            "weight": SEVERITY_WEIGHTS["Low"]
        })

    return findings


# ─────────────────────────────────────────────
# CVE ANALYSIS
# ─────────────────────────────────────────────
def analyze_vulns(vuln_data: Dict) -> List[Dict]:
    findings = []
    for v in vuln_data.get("findings", []):
        findings.append({
            "type": "cve",
            "cve": v["cve"],
            "technology": v["technology"],
            "severity": v["severity"],
            "cvss": v["cvss"],
            "description": v["description"],
            "weight": SEVERITY_WEIGHTS.get(v["severity"], 0)
        })
    return findings


# ─────────────────────────────────────────────
# ENDPOINT ANALYSIS
# ─────────────────────────────────────────────
def analyze_endpoints(crawler_data: Dict) -> List[Dict]:
    findings = []

    high = crawler_data.get("prioritized", {}).get("high", [])
    medium = crawler_data.get("prioritized", {}).get("medium", [])

    if len(high) >= 3:
        findings.append({
            "type": "endpoint",
            "severity": "High",
            "description": f"{len(high)} high-value endpoints detected (/admin, /login)",
            "weight": SEVERITY_WEIGHTS["High"] * 0.7
        })
    elif len(high) >= 1:
        findings.append({
            "type": "endpoint",
            "severity": "Medium",
            "description": f"{len(high)} high-value endpoint(s) detected",
            "weight": SEVERITY_WEIGHTS["Medium"] * 0.7
        })

    if len(medium) >= 5:
        findings.append({
            "type": "endpoint",
            "severity": "Low",
            "description": f"{len(medium)} API/medium endpoints found",
            "weight": SEVERITY_WEIGHTS["Low"]
        })

    return findings


# ─────────────────────────────────────────────
# ATTACK SURFACE SCORING
# ─────────────────────────────────────────────
def calculate_attack_surface(scan_data: Dict) -> tuple:
    """
    Returns (surface_level, multiplier)
    surface_level: "large" | "medium" | "small"
    multiplier: float used to cap risk level
    """
    subdomain_count = len(scan_data.get("subdomains", {}).get("total", []))
    alive_count     = scan_data.get("alive_hosts", {}).get("alive_count", 0)
    open_port_count = len([p for p in scan_data.get("ports", []) if p.get("status") == "open"])

    # Score attack surface 0–10
    surface_score = 0
    surface_score += min(subdomain_count / 5, 4.0)   # max 4 pts from subdomains
    surface_score += min(alive_count / 3, 3.0)        # max 3 pts from alive hosts
    surface_score += min(open_port_count / 2, 3.0)    # max 3 pts from open ports

    if surface_score >= 5.0:
        return "large", 1.0       # full risk allowed
    elif surface_score >= 2.0:
        return "medium", 0.75     # cap at HIGH
    else:
        return "small", 0.5       # cap at MEDIUM


# ─────────────────────────────────────────────
# HONEST SCORE CALCULATION
# ─────────────────────────────────────────────
def calculate_honest_score(all_findings: List[Dict], scan_data: Dict = None) -> float:
    """
    Builds score from ALL real factors — not just CVE average.
    Each factor contributes a capped portion to final 0-10 score.

    Weights:
      CVE severity     → max 4.0  (most important)
      Open ports       → max 2.0
      Attack surface   → max 2.0  (subdomains + alive hosts)
      Endpoints        → max 1.0
      Wayback          → max 1.0
    Total max          = 10.0
    """

    cve_findings      = [f for f in all_findings if f["type"] == "cve"]
    port_findings     = [f for f in all_findings if f["type"] == "port"]
    wayback_findings  = [f for f in all_findings if f["type"] == "wayback"]
    endpoint_findings = [f for f in all_findings if f["type"] == "endpoint"]

    # ── CVE contribution (max 4.0) ──────────────────────────
    if cve_findings:
        max_cve   = max(f["weight"] for f in cve_findings)   # highest single CVE
        avg_cve   = sum(f["weight"] for f in cve_findings) / len(cve_findings)
        cve_score = min((max_cve * 0.6 + avg_cve * 0.4) / 10 * 4.0, 4.0)
    else:
        cve_score = 0.0

    # ── Port contribution (max 2.0) ─────────────────────────
    port_raw   = sum(f["weight"] for f in port_findings)
    port_score = min(port_raw / 10 * 2.0, 2.0)

    # ── Attack surface contribution (max 2.0) ───────────────
    if scan_data:
        subdomain_count = len(scan_data.get("subdomains", {}).get("total", []))
        alive_count     = scan_data.get("alive_hosts", {}).get("alive_count", 0)
        # log-like scaling: 50 subdomains = full 2.0, 1 subdomain ≈ 0.2
        sub_pts   = min(subdomain_count / 25, 1.0)
        alive_pts = min(alive_count / 15, 1.0)
        surface_score = (sub_pts + alive_pts)   # max 2.0
    else:
        surface_score = 1.0  # neutral if no scan_data

    # ── Endpoint contribution (max 1.0) ─────────────────────
    endpoint_raw   = sum(f["weight"] for f in endpoint_findings)
    endpoint_score = min(endpoint_raw / 7 * 1.0, 1.0)

    # ── Wayback contribution (max 1.0) ──────────────────────
    wayback_raw   = sum(f["weight"] for f in wayback_findings)
    wayback_score = min(wayback_raw / 4 * 1.0, 1.0)

    total = cve_score + port_score + surface_score + endpoint_score + wayback_score
    return round(min(total, 10.0), 1)


# ─────────────────────────────────────────────
# RISK CALCULATION
# ─────────────────────────────────────────────
def calculate_risk_level(all_findings: List[Dict], scan_data: Dict = None) -> tuple:
    if not all_findings:
        return "INFO", 0.0

    risk_score = calculate_honest_score(all_findings, scan_data)

    # Pure score-based level — honest and simple
    if risk_score >= 8.0:
        level = "CRITICAL"
    elif risk_score >= 6.0:
        level = "HIGH"
    elif risk_score >= 3.0:
        level = "MEDIUM"
    elif risk_score >= 1.0:
        level = "LOW"
    else:
        level = "INFO"

    return level, risk_score


# ─────────────────────────────────────────────
# NEXT STEPS
# ─────────────────────────────────────────────
def generate_next_steps(all_findings: List[Dict], detected_tech: List[str]) -> List[str]:
    steps = []

    for f in all_findings:
        if f["type"] == "cve" and f["severity"] in ["Critical", "High"]:
            steps.append(f"Exploit {f['cve']} on {f['technology']} — {f['description']}")

    if not steps:
        steps.append("Run Gobuster for directory brute force")
        steps.append("Run full Nmap version scan")
        steps.append("Check all subdomains individually")

    return list(dict.fromkeys(steps))[:8]


# ─────────────────────────────────────────────
# MAIN ENGINE
# ─────────────────────────────────────────────
def run_risk_engine(
    vuln_data: Dict,
    port_data: List[Dict],
    wayback_data: Dict,
    detected_tech: List[str],
    crawler_data: Dict,
    scan_data: Dict = None        # ← new optional param for attack surface
) -> Dict:

    port_findings     = analyze_ports(port_data)
    wayback_findings  = analyze_wayback(wayback_data)
    vuln_findings     = analyze_vulns(vuln_data)
    endpoint_findings = analyze_endpoints(crawler_data)

    all_findings = vuln_findings + port_findings + wayback_findings + endpoint_findings

    # Attack surface awareness
    surface_level = "large"   # default — no cap
    surface_label = "Unknown"
    if scan_data:
        surface_level, _ = calculate_attack_surface(scan_data)
        surface_label = surface_level.capitalize()

    risk_level, risk_score = calculate_risk_level(all_findings, scan_data)
    next_steps = generate_next_steps(all_findings, detected_tech)

    breakdown = {
        "cve":       sum(f["weight"] for f in vuln_findings),
        "ports":     sum(f["weight"] for f in port_findings),
        "wayback":   sum(f["weight"] for f in wayback_findings),
        "endpoints": sum(f["weight"] for f in endpoint_findings),
    }

    risk_reasons = []
    for f in sorted(all_findings, key=lambda x: x["weight"], reverse=True)[:6]:
        risk_reasons.append(f["description"])

    return {
        "risk_level":     risk_level,
        "risk_score":     risk_score,
        "attack_surface": surface_label,
        "breakdown":      breakdown,
        "risk_reasons":   risk_reasons,
        "next_steps":     next_steps
    }