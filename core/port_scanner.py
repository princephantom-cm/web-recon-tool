import asyncio
import socket
from typing import List, Dict

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888
]

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1723: "PPTP", 3306: "MySQL",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt"
}

async def grab_banner(host: str, port: int) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
        banner = await asyncio.wait_for(reader.read(1024), timeout=10)
        writer.close()
        await writer.wait_closed()
        return banner.decode(errors="ignore").strip()
    except Exception:
        return ""

async def scan_port(host: str, port: int) -> Dict:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
        writer.close()
        await writer.wait_closed()
        banner = await grab_banner(host, port)
        return {
            "port": port,
            "status": "open",
            "service": SERVICE_MAP.get(port, "unknown"),
            "banner": banner
        }
    except Exception:
        return {
            "port": port,
            "status": "closed",
            "service": SERVICE_MAP.get(port, "unknown"),
            "banner": ""
        }

async def scan_target(host: str, ports: List[int] = None) -> List[Dict]:
    if ports is None:
        ports = COMMON_PORTS
    tasks = [scan_port(host, port) for port in ports]
    results = await asyncio.gather(*tasks)
    open_ports = [r for r in results if r["status"] == "open"]
    return open_ports

def run_scan(host: str, ports: List[int] = None) -> List[Dict]:
    return asyncio.run(scan_target(host, ports))