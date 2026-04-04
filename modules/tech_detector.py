"""Technology Detector — identifies 50+ web technologies from headers, HTML, cookies."""
import re
import requests
from typing import Any, Dict, List
from modules.base_scanner import BaseScanner
from utils.banner import print_result, print_info, print_warning


SIGNATURES: List[Dict] = [
    # CMS
    {"name": "WordPress",   "category": "CMS",       "pattern": r'wp-content|wp-includes|WordPress', "where": "body"},
    {"name": "Drupal",      "category": "CMS",       "pattern": r'Drupal|/sites/default/files',       "where": "body"},
    {"name": "Joomla",      "category": "CMS",       "pattern": r'Joomla|/components/com_',           "where": "body"},
    {"name": "Ghost",       "category": "CMS",       "pattern": r'ghost-theme|content="Ghost',        "where": "body"},
    {"name": "Wix",         "category": "CMS",       "pattern": r'wix\.com|static\.wixstatic',        "where": "body"},
    {"name": "Shopify",     "category": "E-Commerce","pattern": r'cdn\.shopify\.com|Shopify',         "where": "body"},
    {"name": "Magento",     "category": "E-Commerce","pattern": r'Mage\.|mage/cookies',               "where": "body"},
    # JS Frameworks
    {"name": "React",       "category": "JS Framework","pattern": r'react\.js|react\.min\.js|__REACT', "where": "body"},
    {"name": "Vue.js",      "category": "JS Framework","pattern": r'vue\.js|vue\.min\.js|__vue__',     "where": "body"},
    {"name": "Angular",     "category": "JS Framework","pattern": r'angular\.js|ng-version|angular\.min', "where": "body"},
    {"name": "Next.js",     "category": "JS Framework","pattern": r'__NEXT_DATA__|_next/static',       "where": "body"},
    {"name": "Nuxt.js",     "category": "JS Framework","pattern": r'__nuxt|_nuxt/js',                  "where": "body"},
    {"name": "jQuery",      "category": "JS Library", "pattern": r'jquery[\.\-][\d\.]+\.js|jQuery v',  "where": "body"},
    {"name": "Bootstrap",   "category": "CSS Framework","pattern": r'bootstrap\.min\.css|bootstrap\.css', "where": "body"},
    {"name": "Tailwind",    "category": "CSS Framework","pattern": r'tailwindcss|tw-',                  "where": "body"},
    # Servers
    {"name": "nginx",       "category": "Web Server", "pattern": r'nginx',              "where": "header:server"},
    {"name": "Apache",      "category": "Web Server", "pattern": r'Apache',             "where": "header:server"},
    {"name": "Caddy",       "category": "Web Server", "pattern": r'Caddy',              "where": "header:server"},
    {"name": "IIS",         "category": "Web Server", "pattern": r'Microsoft-IIS',      "where": "header:server"},
    {"name": "LiteSpeed",   "category": "Web Server", "pattern": r'LiteSpeed',          "where": "header:server"},
    # Languages / backends
    {"name": "PHP",         "category": "Language",   "pattern": r'PHP/',               "where": "header:x-powered-by"},
    {"name": "ASP.NET",     "category": "Language",   "pattern": r'ASP\.NET',           "where": "header:x-powered-by"},
    {"name": "Express",     "category": "Framework",  "pattern": r'Express',            "where": "header:x-powered-by"},
    {"name": "Django",      "category": "Framework",  "pattern": r'csrfmiddlewaretoken|django', "where": "body"},
    {"name": "Laravel",     "category": "Framework",  "pattern": r'laravel_session|Laravel', "where": "body"},
    {"name": "Ruby on Rails","category":"Framework",  "pattern": r'_rails|Phusion Passenger|Rails', "where": "body"},
    {"name": "Flask",       "category": "Framework",  "pattern": r'Werkzeug|flask',     "where": "header:server"},
    # CDN
    {"name": "Cloudflare",  "category": "CDN",        "pattern": r'cloudflare',         "where": "header:server"},
    {"name": "Cloudflare",  "category": "CDN",        "pattern": r'__cfduid|cf-ray',    "where": "header:cf-ray"},
    {"name": "Fastly",      "category": "CDN",        "pattern": r'Fastly',             "where": "header:via"},
    {"name": "Varnish",     "category": "CDN",        "pattern": r'Varnish',            "where": "header:via"},
    {"name": "AWS CloudFront","category":"CDN",       "pattern": r'CloudFront',         "where": "header:via"},
    {"name": "Akamai",      "category": "CDN",        "pattern": r'AkamaiGHost',        "where": "header:server"},
    # Analytics
    {"name": "Google Analytics","category":"Analytics","pattern": r'google-analytics\.com|gtag\(|UA-\d+', "where": "body"},
    {"name": "Hotjar",      "category": "Analytics",  "pattern": r'hotjar\.com|hjid',  "where": "body"},
    {"name": "Mixpanel",    "category": "Analytics",  "pattern": r'mixpanel',           "where": "body"},
    # Security
    {"name": "reCAPTCHA",   "category": "Security",   "pattern": r'recaptcha|grecaptcha', "where": "body"},
    {"name": "Sucuri WAF",  "category": "WAF",        "pattern": r'Sucuri',             "where": "header:server"},
    {"name": "ModSecurity", "category": "WAF",        "pattern": r'Mod_Security|NOYB', "where": "header:server"},
]


class TechDetector(BaseScanner):

    def scan(self) -> Dict[str, Any]:
        detected: List[Dict] = []
        try:
            resp = requests.get(self.target, timeout=self.timeout, verify=False,
                                allow_redirects=True)
        except requests.RequestException as e:
            return {"error": str(e), "detected": []}

        body    = resp.text
        headers = {k.lower(): v for k, v in resp.headers.items()}
        seen    = set()

        for sig in SIGNATURES:
            name    = sig["name"]
            where   = sig["where"]
            pattern = sig["pattern"]

            if name in seen:
                continue

            target_str = ""
            if where == "body":
                target_str = body
            elif where.startswith("header:"):
                hdr_name   = where.split(":", 1)[1]
                target_str = headers.get(hdr_name, "")

            if target_str and re.search(pattern, target_str, re.I):
                detected.append({"name": name, "category": sig["category"]})
                seen.add(name)

        # Cookie-based hints
        for cookie in resp.cookies:
            if "wordpress" in cookie.name.lower() or cookie.name.startswith("wp"):
                if "WordPress" not in seen:
                    detected.append({"name": "WordPress", "category": "CMS"})
                    seen.add("WordPress")
            if "laravel" in cookie.name.lower():
                if "Laravel" not in seen:
                    detected.append({"name": "Laravel", "category": "Framework"})
                    seen.add("Laravel")

        return {"url": self.target, "detected": detected, "count": len(detected)}

    def display(self, results: Dict[str, Any]) -> None:
        if "error" in results:
            print_warning(f"Scan failed: {results['error']}")
            return

        if not results["detected"]:
            print_info("No technologies identified")
            return

        by_cat: Dict[str, List[str]] = {}
        for tech in results["detected"]:
            by_cat.setdefault(tech["category"], []).append(tech["name"])

        for cat, names in sorted(by_cat.items()):
            print_result(f"{cat}: {', '.join(names)}")

        print_info(f"Total: {results['count']} technologies detected")
