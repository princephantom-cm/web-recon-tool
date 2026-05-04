import dns.resolver
import dns.reversename
from typing import Dict, List

DNS_RECORD_TYPES = [
    "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA",
    "PTR", "SRV", "CAA", "NAPTR", "DS", "DNSKEY",
    "TLSA", "HINFO", "RP", "LOC", "SPF"
]

def query_record(domain: str, record_type: str) -> List[str]:
    results = []
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=5)
        for rdata in answers:
            results.append(str(rdata))
    except Exception:
        pass
    return results

def check_spf(txt_records: List[str]) -> Dict:
    for record in txt_records:
        if record.startswith("v=spf1"):
            if "-all" in record:
                return {"found": True, "record": record, "status": "Strict", "severity": "Info"}
            elif "~all" in record:
                return {"found": True, "record": record, "status": "Soft Fail", "severity": "Low"}
            else:
                return {"found": True, "record": record, "status": "Weak", "severity": "Medium"}
    return {"found": False, "record": "", "status": "Missing", "severity": "High"}

def check_dmarc(domain: str) -> Dict:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            record = str(rdata)
            if "v=DMARC1" in record:
                if "p=reject" in record:
                    return {"found": True, "record": record, "status": "Strict", "severity": "Info"}
                elif "p=quarantine" in record:
                    return {"found": True, "record": record, "status": "Quarantine", "severity": "Low"}
                else:
                    return {"found": True, "record": record, "status": "None Policy", "severity": "Medium"}
    except Exception:
        pass
    return {"found": False, "record": "", "status": "Missing", "severity": "High"}

def check_dkim(domain: str) -> Dict:
    selectors = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]
    for selector in selectors:
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT", lifetime=5)
            for rdata in answers:
                record = str(rdata)
                if "v=DKIM1" in record:
                    return {"found": True, "selector": selector, "record": record[:100], "severity": "Info"}
        except Exception:
            continue
    return {"found": False, "selector": "", "record": "", "severity": "Medium"}

def run_dns_recon(domain: str) -> Dict:
    records = {}

    for rtype in DNS_RECORD_TYPES:
        records[rtype] = query_record(domain, rtype)

    txt_records = records.get("TXT", [])
    spf = check_spf(txt_records)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)

    email_security_issues = []
    if not spf["found"]:
        email_security_issues.append("SPF record missing — email spoofing possible")
    elif spf["severity"] in ["Medium", "High"]:
        email_security_issues.append(f"SPF weak — {spf['status']}")

    if not dmarc["found"]:
        email_security_issues.append("DMARC record missing — phishing risk")
    elif dmarc["severity"] in ["Medium", "High"]:
        email_security_issues.append(f"DMARC weak — {dmarc['status']}")

    if not dkim["found"]:
        email_security_issues.append("DKIM not found — email integrity not verified")

    return {
        "domain": domain,
        "records": records,
        "email_security": {
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "issues": email_security_issues
        },
        "a_records": records.get("A", []),
        "mx_records": records.get("MX", []),
        "ns_records": records.get("NS", []),
        "txt_records": txt_records,
    }