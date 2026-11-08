#!/usr/bin/env python3
"""Render docs/test-cases-observed.json as a Markdown table (pasted into TESTING.md, never hand-edited)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / (sys.argv[1] if len(sys.argv) > 1 else "docs/test-cases-observed.json")).read_text())
print(f"Generated {data['generated_at']} by `scripts/run_cases.py` against the running API.\n")
print("| ID | Group | Input (defanged/redacted) | Why | Expected | Observed (rule) | Match | Key findings | Coverage | AI |")
print("|---|---|---|---|---|---|---|---|---|---|")
for r in data["results"]:
    ai = r["ai"]
    ai_s = f"{ai['status']}" + (f" ({ai['model']})" if ai.get("model") else "") + (" · injection flagged" if ai.get("injection_flag") else "")
    inp = r["input_display"].replace("|", "\\|")[:90]
    print(f"| {r['id']} | {r['group']} | {inp} | {r['why']} | {' / '.join(r['expected'])} | **{r['observed']}** ({r['rule']}) | "
          f"{'yes' if r['pass'] else 'NO'} | {'; '.join(r['key_findings'][:4]).replace('|', '/') or '–'} | {r['coverage']} | {ai_s} |")
n = len(data["results"])
print(f"\n{sum(r['pass'] for r in data['results'])} of {n} cases matched their expected classification.")
