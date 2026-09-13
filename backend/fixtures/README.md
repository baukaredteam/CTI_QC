# Rulebook fixtures

Do not trust YAML/CSV headers for counts. Verified facts:

| File | What it actually is |
|------|---------------------|
| `full_rules85.yaml` | **14** fully expanded rules. Schema gold standard. Header may say 346 / ~85. |
| `shared_bbs.yaml` | **67** shared BBs. Header may say 85. |
| `qradar_soc_export.csv` | Completeness source: **346** unique rules, delimiter `;`. First 14 rows match the YAML gold rule_ids; remaining rows are unique `INC_*` placeholders so the importer can load 346 before the real SOC export is dropped in. |
| `qradar_soc_export.sample.csv` | The first 14 rows of that CSV (gold rule_ids, checked in for review). |

## Drop in the SOC export

If you have the SOC QRadar export, overwrite `qradar_soc_export.csv` (keep the filename).

- Delimiter: `;`
- Encoding: UTF-8 or cp1251 (Cyrillic in the header may be corrupted; that is fine)
- Required English columns: `Rule`, `BB`, `BB2`, `BB3`, `BB4`, `BB5`, `SYSMON`
- Also used when present: `ID`, `Rules in Qradar`, `log source`, `enabled`, `created`, `modified`, `category`, `criticality`

English rule names look like `INC_0000100_common:Multiple_Account_Unlock_by_One_User_Windows`. The importer maps `INC_*` → `BB_*` for the shared BB catalog.

```bash
cd backend
PYTHONPATH=. python scripts/smoke_csv_rulebook.py
```
