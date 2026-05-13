# aegisgraph/workbench/

Reviewer workbench — strictly CLI-only. Wave 8B (M8-M10 deliverable).

## Commands

```
aegisgraph workbench list [--engine ENGINE] [--target TARGET] [--claim-state STATE] [--format {table,json}]
aegisgraph workbench show RECORD_ID [--format {markdown,json}]
aegisgraph workbench promote RECORD_ID --to STATE [--actor EMAIL] [--justification TEXT]
aegisgraph workbench packet [--top N=10] [--out DIR] [--filter EXPR]
```

`make reviewer-packet` runs `aegisgraph workbench packet --top 10 --out exports/reviewer-packet`.

## Constraints

- No web frameworks (Flask / FastAPI / aiohttp). Negative test:
  `tests/workbench/test_no_web_imports.py`.
- No TUI surfaces (curses / textual / rich.live / prompt_toolkit).
  Negative test: `tests/workbench/test_no_tui_imports.py`.
- ADR-0010 additive: `promote` writes a NEW record at
  `aegisgraph/workbench/promotions/<ISO_DATE>/<id>+<state>.json` with
  `supersedes: <prior_id>` and `hash_chain.previous_hash` linked to
  the prior record_hash. Prior records are never edited.
- Sanitize-check (Rules 1-9 + BLOCKING_PATTERNS) is applied to the
  emitted packet's per-finding tree before the manifest is finalized.
- No live target probing; registry scans on-disk files only.
- Top-N is sorted by `score_vector.total` descending.
