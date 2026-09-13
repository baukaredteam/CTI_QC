"""Load the 346-rule SOC CSV + shared BB catalog and print the resolution report.

Run from backend/ with PYTHONPATH=.:
    python scripts/smoke_csv_rulebook.py
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

CSV_PATH = BACKEND_DIR / "fixtures" / "qradar_soc_export.csv"
SHARED_PATH = BACKEND_DIR / "fixtures" / "shared_bbs.yaml"


def main() -> int:
    if not CSV_PATH.exists():
        print("ERROR: %s not found. Drop the SOC export CSV there (see fixtures/README.md)." % CSV_PATH)
        return 1
    if not SHARED_PATH.exists():
        print("ERROR: %s not found" % SHARED_PATH)
        return 1

    from app.services.bb_resolver import (
        load_shared_bbs,
        print_resolution_report,
        resolve_all_rules,
        summarize_resolution,
    )
    from app.services.csv_rules_importer import parse_rules_csv

    rf = parse_rules_csv(CSV_PATH)
    print("CSV unique rules : %d" % len(rf.rules))
    print("CSV metadata     : %s" % rf.metadata)

    shared = load_shared_bbs(SHARED_PATH)
    print("Shared BBs       : %d" % len(shared))
    print()

    results = resolve_all_rules(rf, shared)
    summary = summarize_resolution(results)
    print(
        "COUNTS bb_chain=%d effective_fallback=%d missing_bb_rules=%d missing_bb_ids=%d errors=%d"
        % (
            summary.bb_chain,
            summary.effective_fallback,
            summary.rules_with_missing_bb,
            summary.missing_bb_count,
            summary.errors,
        )
    )
    print()
    print_resolution_report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
