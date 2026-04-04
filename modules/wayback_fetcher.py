"""Wayback Machine Fetcher — historical URLs, API endpoints, forgotten paths."""
import re
import requests
from typing import Any, Dict, List
from modules.base_scanner import BaseScanner
from utils.banner import print_result, print_info, print_warning, print_high


INTERESTING_EXTS = {
    "config": [".env", ".config", ".cfg", ".ini", ".conf", ".yaml", ".yml", ".toml"],
    "backup": [".bak", ".backup", ".old", ".orig", ".copy", ".zip", ".tar", ".gz", ".sql"],
    "source": [".php~", ".asp~", ".py~", ".rb~", ".js.map", ".ts"],
    "secrets": ["secret", "password", "passwd", "credential", "api_key", "token", "private"],
    "admin":   ["admin", "administrator", "panel", "dashboard", "manage", "console"],
    "api":     ["/api/", "/v1/", "/v2/", "/rest/", "/graphql", "/swagger", "/openapi"],
}


def _categorize(url: str) -> List[str]:
    cats = []
    url_lower = url.lower()
    for cat, patterns in INTERESTING_EXTS.items():
        if any(p in url_lower for p in patterns):
            cats.append(cat)
    return cats


class WaybackFetcher(BaseScanner):

    def scan(self) -> Dict[str, Any]:
        cdx_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={self.domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
        )
        all_urls: List[str] = []
        try:
            resp = requests.get(cdx_url, timeout=self.timeout,
                                headers={"User-Agent": "WebReconX/1.0"})
            if resp.status_code == 200:
                rows = resp.json()
                # First row is the header ["original"]
                all_urls = [row[0] for row in rows[1:] if row]
        except Exception as e:
            return {"error": str(e), "urls": [], "interesting": {}}

        # Categorize
        interesting: Dict[str, List[str]] = {}
        for url in all_urls:
            cats = _categorize(url)
            for cat in cats:
                interesting.setdefault(cat, []).append(url)

        # Deduplicate
        for cat in interesting:
            interesting[cat] = sorted(set(interesting[cat]))[:20]

        return {
            "domain": self.domain,
            "total": len(all_urls),
            "interesting": interesting,
            "sample": sorted(set(all_urls))[:30],
        }

    def display(self, results: Dict[str, Any]) -> None:
        if "error" in results:
            print_warning(f"Wayback fetch failed: {results['error']}")
            return

        print_info(f"Total archived URLs: {results['total']}")

        interesting = results.get("interesting", {})
        if not interesting:
            print_info("No particularly interesting paths found")
        else:
            for cat, urls in interesting.items():
                print()
                print_info(f"Category: {cat.upper()} ({len(urls)} URLs)")
                for url in urls[:10]:
                    if cat in ("secrets", "backup", "config"):
                        print_high(url)
                    else:
                        print_result(url)

        if self.verbose:
            print()
            print_info("Sample of all archived URLs:")
            for url in results.get("sample", [])[:15]:
                print_result(url)
