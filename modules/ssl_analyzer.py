"""SSL/TLS Analyzer — certificate validity, expiry, protocol versions, cipher strength."""
import ssl
import socket
from datetime import datetime, timezone
from typing import Any, Dict
from modules.base_scanner import BaseScanner
from utils.banner import print_result, print_warning, print_high, print_medium, print_info


WEAK_PROTOCOLS  = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS_KW = {"RC4", "DES", "3DES", "EXPORT", "NULL", "anon", "MD5"}


class SSLAnalyzer(BaseScanner):

    def scan(self) -> Dict[str, Any]:
        results: Dict[str, Any] = {
            "domain": self.domain,
            "issues": [],
            "info": [],
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()          # (name, protocol, bits)
                    proto  = ssock.version()

            # Protocol check
            results["protocol"] = proto
            if proto in WEAK_PROTOCOLS:
                results["issues"].append(f"Weak protocol in use: {proto}")
            else:
                results["info"].append(f"Protocol: {proto}")

            # Cipher check
            cipher_name, _, bits = cipher
            results["cipher"] = f"{cipher_name} ({bits}-bit)"
            if any(kw in cipher_name.upper() for kw in WEAK_CIPHERS_KW):
                results["issues"].append(f"Weak cipher: {cipher_name}")
            else:
                results["info"].append(f"Cipher: {cipher_name} ({bits}-bit)")

            # Certificate fields
            subject  = dict(x[0] for x in cert.get("subject", []))
            issuer   = dict(x[0] for x in cert.get("issuer", []))
            not_after = cert.get("notAfter", "")

            results["subject"] = subject.get("commonName", "unknown")
            results["issuer"]  = issuer.get("organizationName", "unknown")
            results["not_after"] = not_after

            # Self-signed check
            if subject == issuer:
                results["issues"].append("Self-signed certificate detected")
            else:
                results["info"].append(f"Issuer: {results['issuer']}")

            # Expiry check
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    expiry = expiry.replace(tzinfo=timezone.utc)
                    now    = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    results["days_until_expiry"] = days_left
                    if days_left < 0:
                        results["issues"].append(f"Certificate EXPIRED {abs(days_left)} days ago")
                    elif days_left < 30:
                        results["issues"].append(f"Certificate expiring soon: {days_left} days")
                    else:
                        results["info"].append(f"Certificate valid for {days_left} more days")
                except ValueError:
                    pass

            # SANs
            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            results["san"] = sans
            results["info"].append(f"SANs: {', '.join(sans[:5]) if sans else 'none'}")

        except ssl.SSLError as e:
            results["issues"].append(f"SSL error: {e}")
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            results["issues"].append(f"Connection failed: {e}")

        return results

    def display(self, results: Dict[str, Any]) -> None:
        for msg in results.get("info", []):
            print_result(msg)
        for issue in results.get("issues", []):
            print_high(issue)
        if not results.get("issues"):
            print_result("No SSL/TLS issues detected")
