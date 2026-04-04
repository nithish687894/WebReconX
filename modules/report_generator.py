"""JSON report generator."""
import json
from datetime import datetime
from typing import Any, Dict
from utils.banner import print_result, print_warning


class ReportGenerator:

    def __init__(self, target: str, results: Dict[str, Any], duration: float):
        self.target   = target
        self.results  = results
        self.duration = duration

    def build(self) -> Dict[str, Any]:
        return {
            "meta": {
                "tool":      "WebReconX",
                "version":   "1.0.0",
                "target":    self.target,
                "generated": datetime.utcnow().isoformat() + "Z",
                "duration":  f"{self.duration:.2f}s",
            },
            "results": self.results,
        }

    def save(self, path: str) -> None:
        report = self.build()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, default=str)
            print_result(f"Report saved → {path}")
        except OSError as e:
            print_warning(f"Could not save report: {e}")
