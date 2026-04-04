"""Multi-threaded port scanner with service identification and risk flagging."""
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from modules.base_scanner import BaseScanner
from utils.banner import print_result, print_high, print_warning, print_info


COMMON_PORTS: Dict[int, str] = {
    21: "FTP",       22: "SSH",        23: "Telnet",    25: "SMTP",
    53: "DNS",       80: "HTTP",       110: "POP3",     143: "IMAP",
    443: "HTTPS",    445: "SMB",       3306: "MySQL",   3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC",   6379: "Redis",   8080: "HTTP-Alt",
    8443: "HTTPS-Alt",  8888: "HTTP-Dev", 9200: "Elasticsearch",
    27017: "MongoDB",   11211: "Memcached", 2181: "Zookeeper",
    4848: "GlassFish",  9090: "WebSphere", 7001: "WebLogic",
    8009: "AJP",     1521: "Oracle",   1433: "MSSQL",   6667: "IRC",
}

# Ports that warrant a HIGH severity warning if open
RISKY_PORTS = {23, 445, 3306, 3389, 5432, 5900, 6379, 8888, 9200, 27017, 11211}


def _grab_banner(host: str, port: int, timeout: float = 2.0) -> Optional[str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(256).decode(errors="ignore").strip()[:80]
            except Exception:
                return None
    except Exception:
        return None


def _probe(host: str, port: int, timeout: float) -> Optional[Dict]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        service = COMMON_PORTS.get(port, "unknown")
        banner  = _grab_banner(host, port, timeout)
        return {
            "port": port,
            "service": service,
            "banner": banner,
            "risky": port in RISKY_PORTS,
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


class PortScanner(BaseScanner):

    def scan(self) -> Dict[str, Any]:
        try:
            host = socket.gethostbyname(self.domain)
        except socket.gaierror as e:
            return {"error": str(e), "open": [], "host": self.domain}

        open_ports: List[Dict] = []
        with ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(_probe, host, p, self.timeout): p for p in COMMON_PORTS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    open_ports.append(result)

        open_ports.sort(key=lambda x: x["port"])
        return {"host": host, "open": open_ports, "count": len(open_ports)}

    def display(self, results: Dict[str, Any]) -> None:
        if "error" in results:
            print_warning(f"Scan failed: {results['error']}")
            return

        if not results["open"]:
            print_info("No common ports open")
            return

        print_info(f"Host: {results['host']}")
        for p in results["open"]:
            banner = f"  [{p['banner']}]" if p.get("banner") else ""
            line   = f"{p['port']:<6} {p['service']:<20}{banner}"
            if p["risky"]:
                print_high(f"OPEN  {line}")
            else:
                print_result(f"OPEN  {line}")
        print_info(f"{results['count']} open port(s) found")
