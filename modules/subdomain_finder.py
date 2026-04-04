"""Subdomain Finder — Certificate Transparency (crt.sh) + DNS bruteforce."""
import json
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Set
from modules.base_scanner import BaseScanner
from utils.banner import print_result, print_info, print_warning


# ~100 most common subdomains for bruteforce
WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "mx", "mx1", "mx2", "api", "api2", "app", "admin", "login", "portal",
    "dashboard", "dev", "staging", "test", "qa", "uat", "beta", "demo",
    "cdn", "static", "assets", "media", "img", "images", "files", "docs",
    "support", "help", "status", "monitor", "metrics", "grafana", "kibana",
    "jenkins", "jira", "confluence", "gitlab", "github", "git", "svn",
    "vpn", "remote", "ssh", "rdp", "secure", "auth", "oauth", "sso",
    "blog", "shop", "store", "pay", "checkout", "cart", "forum",
    "m", "mobile", "wap", "touch", "old", "new", "v1", "v2", "v3",
    "intranet", "internal", "corp", "infra", "cloud", "k8s", "docker",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "smtp", "mail2", "webdisk", "cpanel", "whm", "plesk",
    "news", "press", "careers", "jobs", "download", "downloads", "upload",
]


def _crtsh(domain: str, timeout: float) -> Set[str]:
    """Query crt.sh Certificate Transparency logs."""
    found: Set[str] = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout, headers={"User-Agent": "WebReconX/1.0"}
        )
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
    except Exception:
        pass
    return found


def _resolve(subdomain: str) -> Dict[str, str]:
    """Try to resolve a subdomain to an IP."""
    try:
        ip = socket.gethostbyname(subdomain)
        return {"subdomain": subdomain, "ip": ip}
    except socket.gaierror:
        return {}


class SubdomainFinder(BaseScanner):

    def scan(self) -> Dict[str, Any]:
        found: Set[str] = set()

        # 1 — Certificate Transparency
        ct_results = _crtsh(self.domain, self.timeout)
        found.update(ct_results)

        # 2 — DNS bruteforce
        candidates = [f"{w}.{self.domain}" for w in WORDLIST]
        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(_resolve, c): c for c in candidates}
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    found.add(r["subdomain"])

        # Resolve all found subdomains
        resolved: List[Dict] = []
        for sub in sorted(found):
            r = _resolve(sub)
            source = "crt.sh" if sub in ct_results else "bruteforce"
            resolved.append({
                "subdomain": sub,
                "ip": r.get("ip", "unresolved"),
                "source": source,
            })

        return {
            "domain": self.domain,
            "subdomains": resolved,
            "count": len(resolved),
        }

    def display(self, results: Dict[str, Any]) -> None:
        subs = results.get("subdomains", [])
        if not subs:
            print_info("No subdomains discovered")
            return
        for sub in subs:
            ip  = sub.get("ip", "?")
            src = sub.get("source", "")
            print_result(f"{sub['subdomain']:<45} {ip:<18} [{src}]")
        print_info(f"{results['count']} subdomain(s) found")
