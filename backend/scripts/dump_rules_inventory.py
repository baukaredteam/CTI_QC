"""Dump a compact inventory of full_rules85.yaml for M6.1 development."""
import pathlib

import yaml

FIX = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "full_rules85.yaml"
data = yaml.safe_load(FIX.read_text(encoding="utf-8"))
rules = data["rules"]
print(f"total rules: {len(rules)}")
for r in rules:
    avails = sorted({str(cf.get("availability")) for cf in (r.get("custom_fields") or [])})
    advs = sorted({str(cf.get("adversary_control")) for cf in (r.get("custom_fields") or [])})
    print(
        f"{r['rule_id']} enabled={r.get('enabled')} src={r.get('log_source')!r} "
        f"mitre={r.get('mitre_techniques')} sysmon={r.get('sysmon_required')} "
        f"avail={avails} adv={advs}"
    )
