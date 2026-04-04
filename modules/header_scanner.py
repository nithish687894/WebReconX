"""HTTP Security Header Scanner — checks 11 headers, scores and grades the config."""
import requests
from typing import Any, Dict
from modules.base_scanner import BaseScanner
from utils.banner import print_result, print_warning, print_high, print_medium, print_info


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "desc": "Enforces HTTPS and prevents SSL stripping attacks",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "desc": "Prevents XSS and data injection attacks",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "desc": "Prevents clickjacking attacks",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "desc": "Prevents MIME-type sniffing",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "desc": "Controls referrer information sent with requests",
    },
    "Permissions-Policy": {
        "severity": "MEDIUM",
        "desc": "Controls browser feature permissions",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "desc": "Legacy XSS filter (deprecated but still informative)",
    },
    "Cross-Origin-Embedder-Policy": {
        "severity": "LOW",
        "desc": "Controls cross-origin resource embedding",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "LOW",
        "desc": "Controls cross-origin window interactions",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "LOW",
        "desc": "Controls cross-origin resource sharing",
    },
    "Cache-Control": {
        "severity": "LOW",
        "desc": "Controls caching of sensitive responses",
    },
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

SEVERITY_WEIGHT = {"HIGH": 20, "MEDIUM": 10, "LOW": 5}


def _letter_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


class SecurityHeaderScanner(BaseScanner):

    def scan(self) -> Dict[str, Any]:
        try:
            resp = requests.get(self.target, timeout=self.timeout, verify=False,
                                allow_redirects=True)
        except requests.RequestException as e:
            return {"error": str(e), "headers": {}, "missing": [], "leaks": [], "score": 0}

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        present, missing, leaks = {}, [], []

        for hdr, meta in SECURITY_HEADERS.items():
            val = headers_lower.get(hdr.lower())
            if val:
                present[hdr] = {"value": val, **meta}
            else:
                missing.append({"header": hdr, **meta})

        for hdr in INFO_LEAK_HEADERS:
            val = headers_lower.get(hdr.lower())
            if val:
                leaks.append({"header": hdr, "value": val})

        # Score: start at 100, deduct for each missing header by weight
        total_weight = sum(SEVERITY_WEIGHT[m["severity"]] for m in missing)
        score = max(0, 100 - total_weight)

        return {
            "url": self.target,
            "status_code": resp.status_code,
            "present": present,
            "missing": missing,
            "leaks": leaks,
            "score": score,
            "grade": _letter_grade(score),
        }

    def display(self, results: Dict[str, Any]) -> None:
        if "error" in results:
            print_warning(f"Scan failed: {results['error']}")
            return

        for hdr, meta in results["present"].items():
            print_result(f"{hdr}: {meta['value'][:80]}")

        for item in results["missing"]:
            sev = item["severity"]
            msg = f"{item['header']} — {item['desc']}"
            if sev == "HIGH":
                print_high(msg)
            elif sev == "MEDIUM":
                print_medium(msg)
            else:
                print_warning(msg)

        if results["leaks"]:
            print()
            print_warning("Information disclosure via headers:")
            for leak in results["leaks"]:
                print_warning(f"  {leak['header']}: {leak['value']}")

        print()
        grade = results["grade"]
        score = results["score"]
        print_info(f"Security Score: {score}/100  (Grade: {grade})")
