"""Unit tests for WebReconX — no network required."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Import checks ────────────────────────────────────────────────────────────

def test_imports():
    from utils.colors import Colors
    from utils.banner import print_banner, print_result, print_error
    from modules.base_scanner import BaseScanner
    from modules.header_scanner import SecurityHeaderScanner, _letter_grade
    from modules.ssl_analyzer import SSLAnalyzer
    from modules.tech_detector import TechDetector
    from modules.port_scanner import PortScanner
    from modules.dns_recon import DNSRecon, _build_query
    from modules.subdomain_finder import SubdomainFinder
    from modules.wayback_fetcher import WaybackFetcher, _categorize
    from modules.report_generator import ReportGenerator
    print("  PASS  test_imports")


# ── Header scanner ───────────────────────────────────────────────────────────

def test_letter_grades():
    from modules.header_scanner import _letter_grade
    assert _letter_grade(95) == "A+"
    assert _letter_grade(85) == "A"
    assert _letter_grade(75) == "B"
    assert _letter_grade(65) == "C"
    assert _letter_grade(55) == "D"
    assert _letter_grade(30) == "F"
    print("  PASS  test_letter_grades")


# ── DNS module ───────────────────────────────────────────────────────────────

def test_dns_query_build():
    from modules.dns_recon import _build_query
    pkt = _build_query("example.com", 1)
    assert isinstance(pkt, bytes)
    assert len(pkt) > 12        # header + question
    assert b"\x07example\x03com\x00" in pkt
    print("  PASS  test_dns_query_build")


# ── Subdomain finder ─────────────────────────────────────────────────────────

def test_categorize_url():
    from modules.wayback_fetcher import _categorize
    assert "api" in _categorize("https://example.com/api/v1/users")
    assert "admin" in _categorize("https://example.com/admin/dashboard")
    assert _categorize("https://example.com/about") == []
    print("  PASS  test_categorize_url")


# ── Wayback fetcher ──────────────────────────────────────────────────────────

def test_wayback_categorize():
    from modules.wayback_fetcher import _categorize
    assert "backup" in _categorize("https://example.com/db.sql.bak")
    assert "config" in _categorize("https://example.com/.env")
    assert "secrets" in _categorize("https://example.com/api_key.txt")
    assert _categorize("https://example.com/index.html") == []
    print("  PASS  test_wayback_categorize")


# ── Report generator ─────────────────────────────────────────────────────────

def test_report_build():
    from modules.report_generator import ReportGenerator
    rg = ReportGenerator("https://example.com", {"headers": {"status": "completed"}}, 3.14)
    report = rg.build()
    assert report["meta"]["target"] == "https://example.com"
    assert "results" in report
    assert report["meta"]["tool"] == "WebReconX"
    print("  PASS  test_report_build")


# ── Colors ───────────────────────────────────────────────────────────────────

def test_colors_strip():
    from utils.colors import Colors
    colored = f"{Colors.RED}hello{Colors.RESET}"
    assert Colors.strip(colored) == "hello"
    print("  PASS  test_colors_strip")


if __name__ == "__main__":
    tests = [
        test_imports,
        test_letter_grades,
        test_dns_query_build,
        test_categorize_url,
        test_wayback_categorize,
        test_report_build,
        test_colors_strip,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL  {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
