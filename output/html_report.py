import os
from datetime import datetime
from typing import Dict
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_html_report(scan_data: Dict, output_dir: str = "reports") -> str:

    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = scan_data.get("target", "unknown")
    filename = f"{domain}_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    # Risk data
    risk_data = scan_data.get("risk", {})
    risk_priority = risk_data.get("risk_level", "UNKNOWN")
    risk_score = risk_data.get("risk_score", 0)
    reasons = risk_data.get("risk_reasons", [])
    next_steps = risk_data.get("next_steps", [])

    # Subdomains (needed before top_findings)
    subdomain_data = scan_data.get("subdomains", {})
    crtsh_subs = subdomain_data.get("total", [])

    HIGH_KEYWORDS = ["admin", "api", "dev", "test", "staging", "login"]
    top_subs = [s for s in crtsh_subs if any(k in s for k in HIGH_KEYWORDS)][:5]

    subdomain_rows = ""
    for sub in crtsh_subs:
        subdomain_rows += f"<tr><td>{sub}</td><td><span class='badge passive'>passive</span></td></tr>"

    # Alive hosts (needed before top_findings)
    alive_data = scan_data.get("alive_hosts", {})
    alive_count = alive_data.get("alive_count", 0)
    alive_hosts = alive_data.get("alive_hosts", [])
    alive_rows = ""
    for h in alive_hosts[:20]:
        alive_rows += f"""
        <tr>
            <td><a href='{h.get('url', '')}' target='_blank'>{h.get('subdomain', '')}</a></td>
            <td>{h.get('status_code', '')}</td>
            <td>{h.get('server', '')}</td>
            <td style='font-size:12px;color:#8b949e'>{h.get('title', '')[:60]}</td>
        </tr>"""

    # Crawler (needed before top_findings)
    crawler_data = scan_data.get("crawler", {})
    crawler_interesting = crawler_data.get("all_interesting", [])
    crawler_rows = ""
    for url in crawler_interesting[:50]:
        crawler_rows += f"<tr><td><a href='{url}' target='_blank'>{url[:100]}</a></td></tr>"

    # Crawler prioritized sections
    crawler_high   = crawler_data.get("prioritized", {}).get("high", [])
    crawler_medium = crawler_data.get("prioritized", {}).get("medium", [])
    crawler_low    = crawler_data.get("prioritized", {}).get("low", [])

    def make_priority_rows(urls, color, label):
        if not urls:
            return ""
        rows = ""
        for u in urls:
            rows += f"<tr><td><span class='badge' style='background:{color}22;color:{color}'>{label}</span></td><td><a href='{u}' target='_blank'>{u[:100]}</a></td></tr>"
        return rows

    crawler_priority_rows = (
        make_priority_rows(crawler_high,   "#ff4757", "HIGH") +
        make_priority_rows(crawler_medium, "#ffa502", "MEDIUM") +
        make_priority_rows(crawler_low,    "#2ed573", "LOW")
    )

    # 🧠 Top Findings
    top_findings = []

    if risk_priority in ["CRITICAL", "HIGH"]:
        top_findings.append("High risk target — immediate attention required")
    elif risk_priority == "MEDIUM":
        top_findings.append("Moderate risk — further manual testing recommended")
    else:
        top_findings.append("No critical vulnerabilities detected")

    if alive_count > 10:
        top_findings.append(f"{alive_count} live hosts increase attack surface")

    if crawler_data.get("prioritized", {}).get("high"):
        top_findings.append(f"{len(crawler_data['prioritized']['high'])} high-value endpoints found")

    top_findings_html = "".join(f"<li>{f}</li>" for f in top_findings)

    # Risk colors
    risk_colors = {
        "CRITICAL": "#ff4757",
        "HIGH": "#ff6b35",
        "MEDIUM": "#ffa502",
        "LOW": "#2ed573",
        "INFO": "#1e90ff",
        "UNKNOWN": "#747d8c"
    }
    risk_color = risk_colors.get(risk_priority, "#747d8c")

    # Ports
    ports = scan_data.get("ports", [])
    open_ports = [p for p in ports if p.get("status") == "open"]
    port_rows = ""
    for port in open_ports:
        port_rows += f"""
        <tr>
            <td>{port.get('port', '')}</td>
            <td>TCP</td>
            <td><span class='badge open'>OPEN</span></td>
            <td>{port.get('service', '')}</td>
            <td style='color:#8b949e;font-size:12px'>{port.get('banner', '')[:50]}</td>
        </tr>"""

    # Technologies
    tech_data = scan_data.get("technologies", {})
    technologies = tech_data.get("detected_technologies", [])
    tech_badges = ""
    for tech in technologies:
        tech_badges += f"<span class='tech-badge'>{tech}</span>"

    # Vulnerabilities
    vuln_data = scan_data.get("vulnerabilities", {})
    vulnerabilities = vuln_data.get("findings", [])
    vuln_rows = ""
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "INFO")
        sev_color = risk_colors.get(severity, "#747d8c")
        vuln_rows += f"""
        <tr>
            <td><span class='badge' style='background:{sev_color}22;color:{sev_color}'>{severity}</span></td>
            <td style='color:#58a6ff'>{vuln.get('cve', 'N/A')}</td>
            <td>{vuln.get('technology', '')}</td>
            <td>{vuln.get('description', 'N/A')}</td>
            <td>{vuln.get('cvss', 'N/A')}</td>
        </tr>"""

    # Wayback URLs
    wayback_data = scan_data.get("wayback", {})
    interesting = wayback_data.get("all", [])
    interesting_rows = ""
    for url in interesting[:50]:
        interesting_rows += f"<tr><td><a href='{url}' target='_blank'>{url[:100]}</a></td></tr>"

    # JS Analysis
    js_data = scan_data.get("js_analysis", {})
    js_endpoints = js_data.get("api_endpoints", [])
    js_sensitive = js_data.get("sensitive_findings", [])
    js_emails = js_data.get("emails", [])
    js_internal = js_data.get("internal_urls", [])
    js_s3 = js_data.get("s3_buckets", [])

    js_rows = ""
    for sf in js_sensitive[:5]:
        sev = sf.get("severity", "Info")
        sev_color = risk_colors.get(sev.upper(), "#747d8c")
        js_rows += f"<tr><td><span class='badge' style='background:{sev_color}22;color:{sev_color}'>{sev}</span></td><td>{sf.get('value', '')[:80]}</td><td><span class='badge passive'>{sf.get('type', '')}</span></td><td style='font-size:11px;color:#8b949e'>{sf.get('source','')[:60]}</td></tr>"
    for ep in js_endpoints[:10]:
        js_rows += f"<tr><td><span class='badge' style='background:#1e90ff22;color:#1e90ff'>Info</span></td><td>{ep}</td><td><span class='badge passive'>API</span></td><td></td></tr>"
    for em in js_emails[:5]:
        js_rows += f"<tr><td><span class='badge' style='background:#1e90ff22;color:#1e90ff'>Info</span></td><td>{em}</td><td><span class='badge passive'>Email</span></td><td></td></tr>"
    for iu in js_internal[:5]:
        js_rows += f"<tr><td><span class='badge' style='background:#ffa50222;color:#ffa502'>Medium</span></td><td>{iu[:80]}</td><td><span class='badge passive'>Internal</span></td><td></td></tr>"
    for s3 in js_s3[:5]:
        js_rows += f"<tr><td><span class='badge' style='background:#ffa50222;color:#ffa502'>Medium</span></td><td>{s3}</td><td><span class='badge passive'>S3</span></td><td></td></tr>"

    # DNS Records
    dns_data = scan_data.get("dns_recon", {})
    dns_records = dns_data.get("records", {})
    email_security = dns_data.get("email_security", {})
    dns_rows = ""
    for rtype, values in dns_records.items():
        if values:
            for val in values[:3]:
                dns_rows += f"<tr><td><span class='badge passive'>{rtype}</span></td><td style='font-size:12px;word-break:break-all'>{val}</td></tr>"

    # Email security
    spf = email_security.get("spf", {})
    dmarc = email_security.get("dmarc", {})
    dkim = email_security.get("dkim", {})
    email_issues = email_security.get("issues", [])
    email_rows = ""
    for issue in email_issues:
        email_rows += f"<tr><td>⚠️ {issue}</td></tr>"

    # Security Headers
    headers_data = scan_data.get("security_headers", {})
    headers_grade = headers_data.get("grade", "N/A")
    headers_score = headers_data.get("score", 0)
    missing_headers = headers_data.get("missing_headers", [])
    info_disclosure = headers_data.get("info_disclosure", [])
    header_warnings = headers_data.get("warnings", [])

    grade_color = {"A": "#2ed573", "B": "#58a6ff", "C": "#ffa502", "D": "#ff6b35", "F": "#ff4757"}.get(headers_grade, "#747d8c")

    missing_header_rows = ""
    for h in missing_headers:
        sev_color = risk_colors.get(h.get("severity", "Info"), "#747d8c")
        missing_header_rows += f"""
        <tr>
            <td>{h.get('header', '')}</td>
            <td><span class='badge' style='background:{sev_color}22;color:{sev_color}'>{h.get('severity', '')}</span></td>
            <td style='font-size:12px;color:#8b949e'>{h.get('impact', '')}</td>
        </tr>"""

    info_disc_rows = ""
    for h in info_disclosure:
        info_disc_rows += f"<tr><td>{h.get('header', '')}</td><td style='color:#ffa502'>{h.get('value', '')}</td><td style='font-size:12px;color:#8b949e'>{h.get('impact', '')}</td></tr>"

    # Robots + Sitemap
    robots_data = scan_data.get("robots_sitemap", {})
    robots = robots_data.get("robots", {})
    robots_disallowed = robots.get("disallowed", [])
    robots_interesting = robots.get("interesting", [])
    sitemap_count = robots_data.get("sitemap_urls_count", 0)
    robots_rows = ""
    for path in robots_disallowed[:15]:
        is_interesting = path in robots_interesting
        flag = "⚠️ " if is_interesting else ""
        robots_rows += f"<tr><td>{flag}{path}</td></tr>"

    # Risk reasons + next steps
    reasons_html = "".join(f"<li>{r}</li>" for r in reasons)
    next_steps_html = "".join(f"<li>{s}</li>" for s in next_steps)

    # 📊 Risk Breakdown
    breakdown = risk_data.get("breakdown", {})
    breakdown_html = "".join(
        f"<tr><td>{k.upper()}</td><td>{round(v,2)}</td></tr>"
        for k, v in breakdown.items()
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Recon Report — {domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e1a; color: #e0e0e0; min-height: 100vh; }}
        .header {{ background: linear-gradient(135deg, #0d1117 0%, #161b22 100%); border-bottom: 2px solid #30363d; padding: 30px 40px; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ font-size: 28px; color: #58a6ff; letter-spacing: 2px; text-transform: uppercase; }}
        .header h1 span {{ color: {risk_color}; }}
        .header .meta {{ text-align: right; font-size: 13px; color: #8b949e; }}
        .header .meta p {{ margin: 3px 0; }}
        .container {{ max-width: 1300px; margin: 0 auto; padding: 30px 20px; }}
        .risk-banner {{ background: linear-gradient(135deg, {risk_color}22, {risk_color}11); border: 2px solid {risk_color}; border-radius: 12px; padding: 25px 30px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }}
        .risk-banner .risk-label {{ font-size: 14px; color: #8b949e; margin-bottom: 5px; }}
        .risk-banner .risk-value {{ font-size: 36px; font-weight: bold; color: {risk_color}; }}
        .risk-score-circle {{ width: 100px; height: 100px; border-radius: 50%; border: 4px solid {risk_color}; display: flex; flex-direction: column; justify-content: center; align-items: center; background: {risk_color}22; }}
        .risk-score-circle .score {{ font-size: 28px; font-weight: bold; color: {risk_color}; }}
        .risk-score-circle .score-label {{ font-size: 11px; color: #8b949e; }}
        .cards {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 15px; margin-bottom: 30px; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 20px; text-align: center; transition: transform 0.2s, border-color 0.2s; }}
        .card:hover {{ transform: translateY(-3px); border-color: #58a6ff; }}
        .card .card-value {{ font-size: 32px; font-weight: bold; color: #58a6ff; margin-bottom: 8px; }}
        .card .card-label {{ font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }}
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; margin-bottom: 25px; overflow: hidden; }}
        .section-header {{ background: #0d1117; padding: 15px 20px; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 10px; }}
        .section-header h2 {{ font-size: 16px; color: #58a6ff; text-transform: uppercase; letter-spacing: 1px; }}
        .section-header .count {{ background: #58a6ff22; color: #58a6ff; padding: 2px 10px; border-radius: 20px; font-size: 12px; }}
        .section-header .grade {{ padding: 2px 12px; border-radius: 20px; font-size: 14px; font-weight: bold; background: {grade_color}22; color: {grade_color}; border: 1px solid {grade_color}44; }}
        .section-body {{ padding: 20px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #0d1117; padding: 10px 15px; text-align: left; font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; border-bottom: 1px solid #30363d; }}
        td {{ padding: 10px 15px; border-bottom: 1px solid #21262d; font-size: 13px; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: #1c2128; }}
        .badge {{ padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; }}
        .badge.passive {{ background: #1e90ff22; color: #1e90ff; }}
        .badge.active {{ background: #2ed57322; color: #2ed573; }}
        .badge.open {{ background: #2ed57322; color: #2ed573; }}
        .badge.closed {{ background: #ff475722; color: #ff4757; }}
        .tech-badge {{ display: inline-block; background: #58a6ff22; color: #58a6ff; border: 1px solid #58a6ff44; padding: 5px 12px; border-radius: 20px; font-size: 12px; margin: 4px; }}
        .reason-list, .steps-list {{ list-style: none; padding: 0; }}
        .reason-list li, .steps-list li {{ padding: 8px 0; border-bottom: 1px solid #21262d; font-size: 14px; padding-left: 20px; position: relative; }}
        .reason-list li::before {{ content: "⚠️"; position: absolute; left: 0; }}
        .steps-list li::before {{ content: "→"; position: absolute; left: 0; color: #58a6ff; }}
        .footer {{ text-align: center; padding: 20px; color: #8b949e; font-size: 12px; border-top: 1px solid #30363d; margin-top: 20px; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .empty-msg {{ color: #8b949e; font-style: italic; text-align: center; padding: 20px; }}
        .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
    </style>
</head>
<body>

<div class="header">
    <h1>🔍 Web Recon — <span>{domain}</span></h1>
    <div class="meta">
        <p>🕐 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p>🛠️ Web Recon Tool v1.0.0</p>
        <p>⏱️ Scan Duration: {scan_data.get('scan_duration', 'N/A')}</p>
    </div>
</div>

<div class="container">

    <!-- Risk Banner -->
    <div class="risk-banner">
        <div>
            <div class="risk-label">OVERALL RISK LEVEL</div>
            <div class="risk-value">{risk_priority}</div>
            <div style="color:#8b949e;font-size:13px;margin-top:5px">Target: {domain}</div>
        </div>
        <div class="risk-score-circle">
            <div class="score">{risk_score}</div>
            <div class="score-label">SCORE</div>
        </div>
    </div>

    <!-- 🧠 Top Findings -->
    <div class="section">
        <div class="section-header"><h2>🧠 Top Findings</h2></div>
        <div class="section-body">
            <ul class="reason-list">
                {top_findings_html}
            </ul>
        </div>
    </div>

    <!-- Summary Cards -->
    <div class="cards">
        <div class="card"><div class="card-value">{len(crtsh_subs)}</div><div class="card-label">Subdomains</div></div>
        <div class="card"><div class="card-value">{alive_count}</div><div class="card-label">Live Hosts</div></div>
        <div class="card"><div class="card-value">{len(open_ports)}</div><div class="card-label">Open Ports</div></div>
        <div class="card"><div class="card-value">{vuln_data.get('total_findings', 0)}</div><div class="card-label">CVEs Found</div></div>
        <div class="card"><div class="card-value">{len(js_endpoints)}</div><div class="card-label">JS Endpoints</div></div>
        <div class="card"><div class="card-value">{headers_grade}</div><div class="card-label">Header Grade</div></div>
    </div>

    <!-- Subdomains -->
    <div class="section">
        <div class="section-header"><h2>🌐 Subdomains</h2><span class="count">{len(crtsh_subs)}</span></div>
        <div class="section-body">
            <h3 style="margin-bottom:10px;color:#8b949e;font-size:13px">Top Subdomains</h3>
            <ul>
                {"".join(f"<li>{s}</li>" for s in top_subs) if top_subs else "<li>No high-value subdomains</li>"}
            </ul>
            <details style="margin-top:15px">
                <summary style="cursor:pointer;color:#58a6ff">View All ({len(crtsh_subs)})</summary>
                <table style="margin-top:10px">
                    <thead><tr><th>Subdomain</th><th>Source</th></tr></thead>
                    <tbody>{subdomain_rows}</tbody>
                </table>
            </details>
        </div>
    </div>

    <!-- Alive Hosts -->
    <div class="section">
        <div class="section-header"><h2>✅ Alive Hosts</h2><span class="count">{alive_count}</span></div>
        <div class="section-body">
            {"<table><thead><tr><th>Subdomain</th><th>Status</th><th>Server</th><th>Title</th></tr></thead><tbody>" + alive_rows + "</tbody></table>" if alive_rows else "<div class='empty-msg'>No alive hosts found</div>"}
        </div>
    </div>

    <!-- Open Ports -->
    <div class="section">
        <div class="section-header"><h2>🔌 Open Ports</h2><span class="count">{len(open_ports)}</span></div>
        <div class="section-body">
            {"<table><thead><tr><th>Port</th><th>Protocol</th><th>State</th><th>Service</th><th>Banner</th></tr></thead><tbody>" + port_rows + "</tbody></table>" if port_rows else "<div class='empty-msg'>No open ports found</div>"}
        </div>
    </div>

    <!-- Technologies -->
    <div class="section">
        <div class="section-header"><h2>⚙️ Technologies</h2><span class="count">{len(technologies)}</span></div>
        <div class="section-body">
            {tech_badges if tech_badges else "<div class='empty-msg'>No technologies detected</div>"}
        </div>
    </div>

    <!-- Vulnerabilities -->
    <div class="section">
        <div class="section-header"><h2>🚨 Vulnerabilities</h2><span class="count">{vuln_data.get('total_findings', 0)}</span></div>
        <div class="section-body">
            {"<table><thead><tr><th>Severity</th><th>CVE</th><th>Technology</th><th>Description</th><th>CVSS</th></tr></thead><tbody>" + vuln_rows + "</tbody></table>" if vuln_rows else "<div class='empty-msg'>No vulnerabilities found</div>"}
        </div>
    </div>

    <!-- JS Analysis -->
    <div class="section">
        <div class="section-header"><h2>🔬 JS Analysis</h2><span class="count">{js_data.get('js_files_found', 0)} files</span></div>
        <div class="section-body">
            {"<table><thead><tr><th>Severity</th><th>Finding</th><th>Type</th><th>Source</th></tr></thead><tbody>" + js_rows + "</tbody></table>" if js_rows else "<div class='empty-msg'>No JS findings</div>"}
        </div>
    </div>

    <!-- Crawler -->
    <div class="section">
        <div class="section-header">
            <h2>🕷️ Crawler — Interesting URLs</h2>
            <span class="count">{crawler_data.get('total_interesting', 0)}</span>
            <span style="font-size:11px;color:#ff4757;margin-left:5px">HIGH: {len(crawler_high)}</span>
            <span style="font-size:11px;color:#ffa502;margin-left:5px">MED: {len(crawler_medium)}</span>
            <span style="font-size:11px;color:#2ed573;margin-left:5px">LOW: {len(crawler_low)}</span>
        </div>
        <div class="section-body">
            {"<table><thead><tr><th>Priority</th><th>URL</th></tr></thead><tbody>" + crawler_priority_rows + "</tbody></table>" if crawler_priority_rows else "<div class='empty-msg'>No interesting URLs found</div>"}
        </div>
    </div>

    <!-- Wayback URLs -->
    <div class="section">
        <div class="section-header"><h2>🔗 Historical URLs (Wayback)</h2><span class="count">{len(interesting)}</span></div>
        <div class="section-body">
            {"<table><thead><tr><th>URL</th></tr></thead><tbody>" + interesting_rows + "</tbody></table>" if interesting_rows else "<div class='empty-msg'>No historical URLs found</div>"}
        </div>
    </div>

    <!-- DNS Records -->
    <div class="section">
        <div class="section-header"><h2>🌍 DNS Records</h2></div>
        <div class="section-body">
            <div class="two-col">
                <div>
                    {"<table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>" + dns_rows + "</tbody></table>" if dns_rows else "<div class='empty-msg'>No DNS records found</div>"}
                </div>
                <div>
                    <h3 style="color:#8b949e;font-size:13px;margin-bottom:10px;text-transform:uppercase">Email Security</h3>
                    <table><tbody>
                        <tr><td>SPF</td><td><span class='badge' style='background:{"#2ed57322" if spf.get("found") else "#ff475722"};color:{"#2ed573" if spf.get("found") else "#ff4757"}'>{spf.get("status", "N/A")}</span></td></tr>
                        <tr><td>DMARC</td><td><span class='badge' style='background:{"#2ed57322" if dmarc.get("found") else "#ff475722"};color:{"#2ed573" if dmarc.get("found") else "#ff4757"}'>{dmarc.get("status", "N/A")}</span></td></tr>
                        <tr><td>DKIM</td><td><span class='badge' style='background:{"#2ed57322" if dkim.get("found") else "#ff475722"};color:{"#2ed573" if dkim.get("found") else "#ff4757"}'>{dkim.get("selector", "Not Found") if dkim.get("found") else "Not Found"}</span></td></tr>
                    </tbody></table>
                    {"<br><table><tbody>" + email_rows + "</tbody></table>" if email_rows else ""}
                </div>
            </div>
        </div>
    </div>

    <!-- Security Headers -->
    <div class="section">
        <div class="section-header">
            <h2>🛡️ Security Headers</h2>
            <span class="grade">{headers_grade}</span>
            <span class="count">Score: {headers_score}/10</span>
        </div>
        <div class="section-body">
            <h3 style="color:#8b949e;font-size:13px;margin-bottom:10px;text-transform:uppercase">Missing Headers</h3>
            {"<table><thead><tr><th>Header</th><th>Severity</th><th>Impact</th></tr></thead><tbody>" + missing_header_rows + "</tbody></table>" if missing_header_rows else "<div class='empty-msg'>All headers present</div>"}
            {"<br><h3 style='color:#8b949e;font-size:13px;margin-bottom:10px;text-transform:uppercase'>Info Disclosure</h3><table><thead><tr><th>Header</th><th>Value</th><th>Impact</th></tr></thead><tbody>" + info_disc_rows + "</tbody></table>" if info_disc_rows else ""}
        </div>
    </div>

    <!-- Robots.txt -->
    <div class="section">
        <div class="section-header"><h2>🤖 Robots.txt</h2><span class="count">{len(robots_disallowed)} paths</span></div>
        <div class="section-body">
            {"<p style='color:#8b949e;font-size:12px;margin-bottom:10px'>Sitemap URLs: " + str(sitemap_count) + "</p><table><thead><tr><th>Disallowed Path</th></tr></thead><tbody>" + robots_rows + "</tbody></table>" if robots_rows else "<div class='empty-msg'>No robots.txt found or no disallowed paths</div>"}
        </div>
    </div>

    <!-- Risk Assessment -->
    <div class="section">
        <div class="section-header"><h2>⚠️ Risk Assessment</h2></div>
        <div class="section-body">
            <div class="two-col">
                <div>
                    <h3 style="color:#8b949e;font-size:13px;margin-bottom:10px;text-transform:uppercase">Risk Breakdown</h3>
                    <table>
                        <thead><tr><th>Factor</th><th>Score Contribution</th></tr></thead>
                        <tbody>{breakdown_html}</tbody>
                    </table>
                    <br>
                    <h3 style="color:#8b949e;font-size:13px;margin-bottom:10px;text-transform:uppercase">Risk Reasons</h3>
                    {"<ul class='reason-list'>" + reasons_html + "</ul>" if reasons_html else "<div class='empty-msg'>No risk reasons</div>"}
                </div>
                <div>
                    <h3 style="color:#8b949e;font-size:13px;margin-bottom:10px;text-transform:uppercase">Next Steps</h3>
                    {"<ul class='steps-list'>" + next_steps_html + "</ul>" if next_steps_html else "<div class='empty-msg'>No next steps</div>"}
                </div>
            </div>
        </div>
    </div>

</div>

<div class="footer">
    <p>Generated by Web Recon Tool v1.0.0 | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
</div>

</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath