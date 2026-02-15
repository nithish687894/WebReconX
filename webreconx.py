#!/usr/bin/env python3
"""
WebReconX - Advanced Web Security Reconnaissance Framework
Author: NithishKumar S (@nithish687894)
Version: 1.0.0

A comprehensive web security reconnaissance tool that combines
multiple security scanning modules into a single framework.
"""

import sys
import os
import argparse
import json
import time
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.banner import print_banner, print_section, print_result, print_error, print_info, print_warning
from utils.colors import Colors
from modules.header_scanner import SecurityHeaderScanner
from modules.ssl_analyzer import SSLAnalyzer
from modules.tech_detector import TechDetector
from modules.port_scanner import PortScanner
from modules.dns_recon import DNSRecon
from modules.subdomain_finder import SubdomainFinder
from modules.wayback_fetcher import WaybackFetcher
from modules.report_generator import ReportGenerator


class WebReconX:
    """Main framework class that orchestrates all scanning modules."""

    VERSION = "1.0.0"
    MODULES = {
        "headers": {
            "name": "Security Header Scanner",
            "desc": "Analyzes HTTP security headers and identifies misconfigurations",
            "class": SecurityHeaderScanner
        },
        "ssl": {
            "name": "SSL/TLS Analyzer",
            "desc": "Checks SSL certificate validity, protocol versions, and cipher suites",
            "class": SSLAnalyzer
        },
        "tech": {
            "name": "Technology Detector",
            "desc": "Identifies web technologies, frameworks, and server software",
            "class": TechDetector
        },
        "ports": {
            "name": "Port Scanner",
            "desc": "Scans common ports and identifies running services",
            "class": PortScanner
        },
        "dns": {
            "name": "DNS Reconnaissance",
            "desc": "Enumerates DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)",
            "class": DNSRecon
        },
        "subdomains": {
            "name": "Subdomain Finder",
            "desc": "Discovers subdomains using multiple data sources",
            "class": SubdomainFinder
        },
        "wayback": {
            "name": "Wayback Machine Fetcher",
            "desc": "Retrieves historical URLs and endpoints from Wayback Machine",
            "class": WaybackFetcher
        }
    }

    def __init__(self, target, modules=None, output=None, timeout=10, threads=10, verbose=False):
        self.target = self._clean_target(target)
        self.selected_modules = modules or list(self.MODULES.keys())
        self.output = output
        self.timeout = timeout
        self.threads = threads
        self.verbose = verbose
        self.results = {}
        self.start_time = None
        self.end_time = None

    def _clean_target(self, target):
        """Clean and normalize target URL."""
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target.rstrip("/")

    def _get_domain(self):
        """Extract domain from target URL."""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        return parsed.hostname

    def run(self):
        """Execute all selected scanning modules."""
        print_banner(self.VERSION)
        self.start_time = datetime.now()

        domain = self._get_domain()
        print_info(f"Target    : {self.target}")
        print_info(f"Domain    : {domain}")
        print_info(f"Modules   : {len(self.selected_modules)}")
        print_info(f"Timeout   : {self.timeout}s")
        print_info(f"Started   : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n{Colors.CYAN}{'═' * 70}{Colors.RESET}\n")

        for mod_key in self.selected_modules:
            if mod_key not in self.MODULES:
                print_warning(f"Unknown module: {mod_key}")
                continue

            mod_info = self.MODULES[mod_key]
            print_section(mod_info["name"])

            try:
                scanner = mod_info["class"](
                    target=self.target,
                    domain=domain,
                    timeout=self.timeout,
                    verbose=self.verbose
                )
                result = scanner.scan()
                self.results[mod_key] = {
                    "name": mod_info["name"],
                    "status": "completed",
                    "data": result
                }
                scanner.display(result)

            except KeyboardInterrupt:
                print_warning("\nScan interrupted by user")
                sys.exit(0)
            except Exception as e:
                print_error(f"Module '{mod_key}' failed: {str(e)}")
                self.results[mod_key] = {
                    "name": mod_info["name"],
                    "status": "failed",
                    "error": str(e)
                }

        self.end_time = datetime.now()
        duration = (self.end_time - self.start_time).total_seconds()

        # Print summary
        print(f"\n{Colors.CYAN}{'═' * 70}{Colors.RESET}")
        print_section("Scan Summary")
        print_info(f"Target    : {self.target}")
        print_info(f"Duration  : {duration:.2f} seconds")
        print_info(f"Modules   : {len(self.results)} completed")

        completed = sum(1 for r in self.results.values() if r["status"] == "completed")
        failed = sum(1 for r in self.results.values() if r["status"] == "failed")
        print_result(f"Completed : {completed} | Failed : {failed}")

        # Generate report
        if self.output:
            report = ReportGenerator(self.target, self.results, duration)
            report.save(self.output)
            print_info(f"Report saved to: {self.output}")

        return self.results


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="webreconx",
        description=f"{Colors.GREEN}WebReconX{Colors.RESET} - Advanced Web Security Reconnaissance Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.YELLOW}Examples:{Colors.RESET}
  python webreconx.py example.com                    Full scan
  python webreconx.py example.com -m headers ssl     Specific modules
  python webreconx.py example.com -o report.json     Save report
  python webreconx.py example.com -m ports -t 5      Port scan with 5s timeout
  python webreconx.py example.com --list-modules     List all modules

{Colors.YELLOW}Modules:{Colors.RESET}
  headers     Security Header Scanner
  ssl         SSL/TLS Analyzer
  tech        Technology Detector
  ports       Port Scanner
  dns         DNS Reconnaissance
  subdomains  Subdomain Finder
  wayback     Wayback Machine Fetcher

{Colors.RED}Disclaimer:{Colors.RESET}
  Only use this tool on targets you have permission to scan.
  Unauthorized scanning may be illegal in your jurisdiction.
        """
    )

    parser.add_argument("target", nargs="?", help="Target URL or domain to scan")
    parser.add_argument("-m", "--modules", nargs="+", help="Specific modules to run",
                        choices=["headers", "ssl", "tech", "ports", "dns", "subdomains", "wayback"])
    parser.add_argument("-o", "--output", help="Output file for JSON report")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--list-modules", action="store_true", help="List all available modules")
    parser.add_argument("--version", action="version", version=f"WebReconX v{WebReconX.VERSION}")

    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    if args.list_modules:
        print_banner(WebReconX.VERSION)
        print_section("Available Modules")
        for key, mod in WebReconX.MODULES.items():
            print(f"  {Colors.GREEN}{key:15s}{Colors.RESET} {mod['desc']}")
        print()
        sys.exit(0)

    if not args.target:
        print_banner(WebReconX.VERSION)
        print_error("No target specified. Use -h for help.")
        print_info("Usage: python webreconx.py <target> [options]")
        sys.exit(1)

    scanner = WebReconX(
        target=args.target,
        modules=args.modules,
        output=args.output,
        timeout=args.timeout,
        threads=args.threads,
        verbose=args.verbose
    )

    try:
        scanner.run()
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user")
        sys.exit(0)


if __name__ == "__main__":
    main()
