import asyncio
import argparse
import sys
from datetime import datetime

# Core modules
from core.port_scanner import run_scan
from core.subdomain_enum import run_subdomain_enum
from core.tech_fingerprint import fingerprint_target
from core.vuln_correlator import correlate_vulnerabilities
from core.risk_engine import run_risk_engine
from core.dns_recon import run_dns_recon
from core.security_headers import run_security_headers

# Passive modules
from modules.passive.wayback import run_wayback
from modules.passive.js_analyzer import run_js_analyzer
from modules.passive.robots_sitemap import run_robots_sitemap

# Active modules
from modules.active.http_probe import run_http_probe
from modules.active.crawler import run_crawler

# Output
from output.html_report import generate_html_report
from output.json_report import generate_json_report


def print_banner():
    print("""
\033[36m
 ██╗    ██╗███████╗██████╗     ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██║    ██║██╔════╝██╔══██╗    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██║ █╗ ██║█████╗  ██████╔╝    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║███╗██║██╔══╝  ██╔══██╗    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ╚███╔███╔╝███████╗██████╔╝    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚══╝╚══╝ ╚══════╝╚═════╝     ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
\033[33m  Web Recon Tool v1.0 | Penetration Testing Recon Engine\033[0m
\033[90m  Use responsibly. Only scan targets you have permission to test.\033[0m
    """)
    print("\033[35m  \"The system isn't secure — it's just waiting for you.\"\033[0m\n")


def print_progress(step: int, total: int, module_name: str, status: str = "running"):
    icons = {"running": "⚡", "done": "✅", "skip": "⚠️", "fail": "❌"}
    icon = icons.get(status, "⚡")
    bar_filled = int((step / total) * 20)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    print(f"\r  {icon} [{bar}] Step {step}/{total} — {module_name}", end="", flush=True)
    if status in ("done", "skip", "fail"):
        print()


def run_recon(target: str, output_format: str = "html", max_depth: int = 2):
    print_banner()
    start_time = datetime.now()
    total_steps = 12

    print(f"\n\033[36m[*] Target     : {target}\033[0m")
    print(f"\033[36m[*] Started At  : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\033[0m")
    print(f"\033[36m[*] Output      : {output_format.upper()}\033[0m\n")

    scan_data = {
        "target": target,
        "scan_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
        "tool_version": "v1.0",
        "wayback": {},
        "subdomains": {},
        "alive_hosts": {},
        "ports": [],
        "technologies": {},
        "js_analysis": {},
        "crawler": {},
        "robots_sitemap": {},
        "dns_recon": {},
        "security_headers": {},
        "vulnerabilities": {},
        "risk": {}
    }

    # STEP 1 — Wayback URLs
    step = 1
    print_progress(step, total_steps, "Wayback Machine (Historical URLs)", "running")
    try:
        wayback_data = run_wayback(target)
        scan_data["wayback"] = wayback_data
        print_progress(step, total_steps,
            f"Wayback Done — {wayback_data.get('total_fetched', 0)} URLs fetched", "done")
    except Exception as e:
        scan_data["wayback"] = {}
        print_progress(step, total_steps, f"Wayback Failed — {e}", "fail")

    # STEP 2 — Subdomain Enumeration
    step = 2
    print_progress(step, total_steps, "Subdomain Enumeration (4 sources + brute)", "running")
    try:
        subdomain_data = run_subdomain_enum(target)
        scan_data["subdomains"] = subdomain_data
        total_subs = len(subdomain_data.get("total", []))
        print_progress(step, total_steps,
            f"Subdomains Done — {total_subs} found", "done")
    except Exception as e:
        scan_data["subdomains"] = {}
        print_progress(step, total_steps, f"Subdomain Enum Failed — {e}", "fail")

    # STEP 3 — HTTP Probe
    step = 3
    print_progress(step, total_steps, "HTTP Probe (Alive Host Filtering)", "running")
    try:
        all_subdomains = list(set(
            scan_data["subdomains"].get("passive", []) +
            scan_data["subdomains"].get("active", [])
        ))
        if all_subdomains:
            probe_data = run_http_probe(all_subdomains)
            scan_data["alive_hosts"] = probe_data
            print_progress(step, total_steps,
                f"HTTP Probe Done — {probe_data.get('alive_count', 0)} alive hosts", "done")
        else:
            scan_data["alive_hosts"] = {"alive_count": 0, "alive_hosts": []}
            print_progress(step, total_steps, "HTTP Probe Skipped — No subdomains", "skip")
    except Exception as e:
        scan_data["alive_hosts"] = {}
        print_progress(step, total_steps, f"HTTP Probe Failed — {e}", "fail")

    # STEP 4 — Port Scanning
    step = 4
    print_progress(step, total_steps, "Port Scanning (Async)", "running")
    try:
        port_data = run_scan(target)
        scan_data["ports"] = port_data
        open_ports = [p for p in port_data if p.get("status") == "open"]
        print_progress(step, total_steps,
            f"Port Scan Done — {len(open_ports)} open ports", "done")
        for p in open_ports:
            print(f"      → {p['port']}/{p['service']} — {p.get('banner', '')[:50]}")
    except Exception as e:
        scan_data["ports"] = []
        print_progress(step, total_steps, f"Port Scan Failed — {e}", "fail")

    # STEP 5 — Tech Fingerprinting
    step = 5
    print_progress(step, total_steps, "Technology Fingerprinting", "running")
    try:
        tech_data = fingerprint_target(f"https://{target}")
        scan_data["technologies"] = tech_data
        detected = tech_data.get("detected_technologies", [])
        print_progress(step, total_steps,
            f"Tech Done — {len(detected)} technologies detected", "done")
    except Exception as e:
        scan_data["technologies"] = {}
        print_progress(step, total_steps, f"Tech Fingerprint Failed — {e}", "fail")

    # STEP 6 — JS Analysis
    step = 6
    print_progress(step, total_steps, "JS File Analysis (Secrets & Endpoints)", "running")
    try:
        js_data = run_js_analyzer(target)
        scan_data["js_analysis"] = js_data
        print_progress(step, total_steps,
            f"JS Done — {js_data.get('js_files_found', 0)} files, "
            f"{len(js_data.get('sensitive_findings', []))} sensitive", "done")
    except Exception as e:
        scan_data["js_analysis"] = {}
        print_progress(step, total_steps, f"JS Analysis Failed — {e}", "fail")

    # STEP 7 — Crawler
    step = 7
    print_progress(step, total_steps, f"Crawler (Depth {max_depth})", "running")
    try:
        crawler_data = run_crawler(target, max_depth=max_depth)
        scan_data["crawler"] = crawler_data
        print_progress(step, total_steps,
            f"Crawler Done — {crawler_data.get('total_interesting', 0)} interesting URLs", "done")
    except Exception as e:
        scan_data["crawler"] = {}
        print_progress(step, total_steps, f"Crawler Failed — {e}", "fail")

    # STEP 8 — Robots + Sitemap
    step = 8
    print_progress(step, total_steps, "Robots.txt + Sitemap Analysis", "running")
    try:
        robots_data = run_robots_sitemap(target)
        scan_data["robots_sitemap"] = robots_data
        print_progress(step, total_steps,
            f"Robots Done — {len(robots_data.get('all_interesting', []))} interesting paths", "done")
    except Exception as e:
        scan_data["robots_sitemap"] = {}
        print_progress(step, total_steps, f"Robots/Sitemap Failed — {e}", "fail")

    # STEP 9 — DNS Recon
    step = 9
    print_progress(step, total_steps, "DNS Recon (18 record types)", "running")
    try:
        dns_data = run_dns_recon(target)
        scan_data["dns_recon"] = dns_data
        print_progress(step, total_steps,
            f"DNS Done — {len(dns_data.get('records', {}))} record types", "done")
    except Exception as e:
        scan_data["dns_recon"] = {}
        print_progress(step, total_steps, f"DNS Recon Failed — {e}", "fail")

    # STEP 10 — Security Headers
    step = 10
    print_progress(step, total_steps, "Security Headers Analysis (25 headers)", "running")
    try:
        headers_data = run_security_headers(target)
        scan_data["security_headers"] = headers_data
        print_progress(step, total_steps,
            f"Headers Done — Grade: {headers_data.get('grade', 'N/A')}, "
            f"Score: {headers_data.get('score', 0)}", "done")
    except Exception as e:
        scan_data["security_headers"] = {}
        print_progress(step, total_steps, f"Security Headers Failed — {e}", "fail")

    # STEP 11 — Vuln Correlation
    step = 11
    print_progress(step, total_steps, "Vulnerability Correlation (CVE Mapping)", "running")
    try:
        detected_tech = scan_data["technologies"].get("detected_technologies", []) \
            if isinstance(scan_data["technologies"], dict) else []
        vuln_data = correlate_vulnerabilities(detected_tech)
        scan_data["vulnerabilities"] = vuln_data
        print_progress(step, total_steps,
            f"Vuln Done — {vuln_data.get('total_findings', 0)} CVEs found", "done")
    except Exception as e:
        scan_data["vulnerabilities"] = {}
        print_progress(step, total_steps, f"Vuln Correlation Failed — {e}", "fail")

    # STEP 12 — Risk Engine
    step = 12
    print_progress(step, total_steps, "Risk Engine (Scoring + Prioritization)", "running")
    try:
        detected_tech = scan_data["technologies"].get("detected_technologies", []) \
            if isinstance(scan_data["technologies"], dict) else []
        risk_data = run_risk_engine(
            vuln_data=scan_data["vulnerabilities"] if isinstance(scan_data["vulnerabilities"], dict) else {},
            port_data=scan_data["ports"] if isinstance(scan_data["ports"], list) else [],
            wayback_data=scan_data["wayback"] if isinstance(scan_data["wayback"], dict) else {},
            detected_tech=detected_tech,
            crawler_data=scan_data["crawler"] if isinstance(scan_data["crawler"], dict) else {},
            scan_data=scan_data  # ✅ attack surface awareness
        )
        scan_data["risk"] = risk_data
        print_progress(step, total_steps,
            f"Risk Done — {risk_data.get('risk_level', 'N/A')} "
            f"(Score: {risk_data.get('risk_score', 0)})", "done")
    except Exception as e:
        scan_data["risk"] = {}
        print_progress(step, total_steps, f"Risk Engine Failed — {e}", "fail")

    # OUTPUT
    end_time = datetime.now()
    duration = (end_time - start_time).seconds
    scan_data["scan_duration"] = f"{duration}s"

    print(f"\n\033[33m[*] Scan completed in {duration}s\033[0m")
    print(f"\033[33m[*] Generating report...\033[0m\n")

    if output_format in ("html", "both"):
        try:
            html_path = generate_html_report(scan_data)
            print(f"  \033[32m✅ HTML Report : {html_path}\033[0m")
        except Exception as e:
            print(f"  \033[31m❌ HTML Report Failed : {e}\033[0m")

    if output_format in ("json", "both"):
        try:
            json_path = generate_json_report(scan_data)
            print(f"  \033[32m✅ JSON Report : {json_path}\033[0m")
        except Exception as e:
            print(f"  \033[31m❌ JSON Report Failed : {e}\033[0m")

    print(f"\n\033[36m{'─'*60}\033[0m")
    print(f"\033[36m  Target   : {target}\033[0m")
    print(f"\033[36m  Risk     : {scan_data['risk'].get('risk_level', 'N/A')} "
          f"(Score: {scan_data['risk'].get('risk_score', 'N/A')})\033[0m")
    print(f"\033[36m  Duration : {duration}s\033[0m")
    print(f"\033[36m{'─'*60}\033[0m\n")

    return scan_data


def main():
    parser = argparse.ArgumentParser(
        description="Web Recon Tool — Penetration Testing Recon Engine",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("target", help="Target domain (e.g. hackthebox.com)")
    parser.add_argument("-o", "--output", choices=["html", "json", "both"],
        default="html", help="Output format (default: html)")
    parser.add_argument("-d", "--depth", type=int, default=2,
        help="Crawler depth (default: 2)")

    args = parser.parse_args()

    target = args.target.strip()
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    try:
        run_recon(target=target, output_format=args.output, max_depth=args.depth)
    except KeyboardInterrupt:
        print("\n\n\033[31m[!] Scan interrupted by user.\033[0m\n")
        sys.exit(0)


if __name__ == "__main__":
    main()