# Rulebook fixtures

Do not trust YAML/CSV headers for counts. Verified facts:

| File | What it actually is |
|------|---------------------|
| `full_rules85.yaml` | **14** fully expanded rules. Schema gold standard. Header may say 346 / ~85. |
| `shared_bbs.yaml` | **67** shared BBs. Header may say 85. |
| `qradar_soc_export.csv` | **Not the full SOC export.** Currently the 14 gold `INC_*` rows only (same as the sample). The real export is 346 rows / **345 unique** `INC_*` names after dropping 1 duplicate. This agent never received that attachment. |
| `qradar_soc_export.sample.csv` | The same 14 gold rows, checked in for review. |

S1 / MAR-15 is **not done** until the real SOC export replaces `qradar_soc_export.csv`. Placeholder rows (`SOC_Export_Placeholder`) are forbidden — tests fail if any appear.

## Drop in the SOC export

Overwrite `qradar_soc_export.csv` (keep the filename) with the SOC QRadar export.

- Delimiter: `;`
- Encoding: UTF-8 or cp1251 (Cyrillic in the header may be corrupted; that is fine)
- Columns: `ID;Rules in Qradar;log source;enabled;created;modified;category;criticality;Rule;BB;BB2;BB3;BB4;BB5;SYSMON`
- `Rule` = `INC_NNNNNN_common:Name`
- `BB*` = ids such as `BB_0000100`, `BB_eventype:UserUnlock_Windows`, `BB_common:...`

After the drop-in, unique `INC_*` count after importer dedup must be **345**.

```bash
cd backend
PYTHONPATH=. python scripts/smoke_csv_rulebook.py
```
