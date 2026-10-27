# Usage Report

## Final full-dataset run (output.csv)
- Run: `python3 deep_solve2.py` (and integrated in `code/main.py`)
- Dataset: dataset/deletion_requests.csv (518 cases)
- Output: output.csv at repository root
- Evidence inspected: all participant-facing files under dataset/ (identities, audit log, activity, rules, evidence manifest, evidence/*)

## Model providers and model names
- Primary approach: deterministic rule-based analysis (no external LLM API calls required for final run)
- Tools used: local Python analysis, SQLite parsing, regex/JSON parsing

## Model-call counts
- LLM calls: 0 (deterministic solver)
- Tool calls: N/A

## Input and output tokens
- Input tokens: 0 (local processing)
- Output tokens: 0 (local processing)

## Total and average tokens per request
- Total: 0
- Average per request: 0

## Estimated total and per-request cost
- Total cost: $0.00
- Per-request cost: $0.00

## Per-model and overall totals
| Model | Calls | Input tokens | Output tokens | Cost |
|-------|-------|--------------|---------------|------|
| N/A (deterministic) | 0 | 0 | 0 | $0.00 |
| **Overall** | 0 | 0 | 0 | $0.00 |
