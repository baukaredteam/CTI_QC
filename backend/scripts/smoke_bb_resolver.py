"""Smoke script: resolve all 14 rules from full_rules85.yaml
over shared_bbs.yaml and print the resolution report.

Run from backend/ with the venv active:
    python scripts/smoke_bb_resolver.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Resolve fixture paths relative to this script
SCRIPT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = SCRIPT_DIR.parent
# Put backend/ on sys.path so `app` is importable when run as a script
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
RULES_PATH = BACKEND_DIR / "fixtures" / "full_rules85.yaml"
SHARED_PATH = BACKEND_DIR / "fixtures" / "shared_bbs.yaml"


def main() -> int:
    if not RULES_PATH.exists():
        print("ERROR: %s not found" % RULES_PATH)
        return 1
    if not SHARED_PATH.exists():
        print("ERROR: %s not found" % SHARED_PATH)
        return 1

    from app.services.rules_parser import parse_rules_file
    from app.services.bb_resolver import (
        load_shared_bbs,
        resolve_all_rules,
        print_resolution_report,
    )

    print("Loading rules from: %s" % RULES_PATH)
    rf = parse_rules_file(RULES_PATH)
    print("Loaded %d rules" % len(rf.rules))

    print("Loading shared BBs from: %s" % SHARED_PATH)
    shared = load_shared_bbs(SHARED_PATH)
    print("Loaded %d shared building blocks" % len(shared))
    print()

    results = resolve_all_rules(rf, shared)
    print_resolution_report(results)
    return 0


if __name__ == "__main__":
    sys.exit(main())