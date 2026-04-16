"""
CLI runner for Assignment 11 solution.

What: Runs the pipeline tests and exports `audit_log.json`.
Why: Provides a non-notebook path to produce the required outputs locally.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pipeline import DefensePipeline, run_assignment_tests


def main() -> None:
    """Run the required test suites and export audit log to JSON."""
    # Ensure UTF-8 printing on Windows terminals (avoid UnicodeEncodeError for Vietnamese).
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    pipeline = DefensePipeline()
    summary = run_assignment_tests(pipeline)

    out_dir = Path(__file__).resolve().parent
    audit_path = pipeline.audit_logger.export_json(out_dir / "audit_log.json")

    print("=== Assignment 11: Defense-in-Depth Pipeline ===")
    print(f"Audit log exported: {audit_path}")
    print("Alerts:")
    for a in pipeline.monitor.alerts:
        print(f" - {a}")

    print("\nTest summary (decision + blocked_by):")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
