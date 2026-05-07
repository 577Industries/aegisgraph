"""SMABench orchestrator.

Wires Ring 1 generators (synthetic corpora), Ring 2 runner (real
extraction consumer with graceful degradation), and Ring 3 placeholder
into a single `run(root)` entry point. Emits:

- `smabench/ring1/<corpus>/corpus.metadata.json` — per-corpus manifest
  with deterministic SHA-256 over per-item hashes.
- `smabench/results/<date>/results.json` — top-level harness report.
- `smabench/results/<date>/repeatability.json` — proof of byte-identity
  between two consecutive runs.
- `smabench/results/<date>/delta.json` — diff against the previous
  `smabench/results/latest/` run (if any).
- `smabench/results/<date>/recommendations.json` — schema-conformant
  recommendation cards for high-priority unvalidated nodes.
- `smabench/results/<date>/dashboard.html` — single-file static
  dashboard for the evaluator.
- `smabench/results/latest/` — symlink (or copy on platforms that
  forbid symlinks) pointing at the newest dated directory.

The orchestrator is intentionally idempotent: re-running with the same
inputs produces byte-identical artifacts (modulo the
`generated_at` timestamp, which is excluded from the byte-identity
hash). This is the property the `repeatability.json` flag asserts.

Ring 1 generators that fail (e.g. `qrcode` not installed and an
explicit raise from somewhere unforeseen) are NOT silently skipped —
they're recorded with `status="failed"` plus the exception class so
the operator can see it. Generators whose optional deps are missing
take their own internal fallback path (qr_corpus → placeholder PNG,
media_corpus → raw_minimal headers); those still report
`status="passing"` because the corpus they emit is byte-stable.
"""

from __future__ import annotations

import datetime as _dt
import os
import json
from pathlib import Path
from typing import Any, Callable

from .constants import STATIC_GENERATED_AT
from .io import canonical_json, sha256_bytes, write_json

# Ring 1 generator imports. We import the underscore-named modules
# directly. Each generator exposes `generate(corpus_dir, count, seed) ->
# metadata_dict` and a default count constant (DEFAULT_COUNT).
from smabench.ring1 import (
    deeplink_corpus,
    media_corpus,
    pq_corpus,
    qr_corpus,
    sync_corpus,
    url_corpus,
)
from smabench.ring2.runner import run as run_ring2


# Each tuple: (corpus-dir-name, module, default-count). The corpus dir
# name MUST match the on-disk kebab-case directory; that's the SPEC's
# documented Ring 1 layout and the orchestrator emits metadata at
# `smabench/ring1/<dir>/corpus.metadata.json`.
RING1_GENERATORS: list[tuple[str, Any, int]] = [
    ("url-corpus", url_corpus, url_corpus.DEFAULT_COUNT),
    ("qr-corpus", qr_corpus, qr_corpus.DEFAULT_COUNT),
    ("deeplink-corpus", deeplink_corpus, deeplink_corpus.DEFAULT_COUNT),
    ("sync-corpus", sync_corpus, sync_corpus.DEFAULT_COUNT),
    ("media-corpus", media_corpus, media_corpus.DEFAULT_COUNT),
    ("pq-corpus", pq_corpus, pq_corpus.DEFAULT_COUNT),
]

DEFAULT_SEED = 42

# Allow tests / callers to override the run date deterministically. We
# default to `STATIC_GENERATED_AT` so reproduce-style invocations land
# in `results/2026-05-05`. An env var override lets a developer pin
# their own day without rebooting the calendar.
RUN_DATE_ENV = "AEGISGRAPH_SMABENCH_RUN_DATE"


def _run_date() -> str:
    override = os.environ.get(RUN_DATE_ENV)
    if override:
        return override
    # Use the static generated_at date; it's the same one extraction,
    # reprochain, polydiff use, so all artifacts collide on the same
    # results/<date>/ folder for the canonical reproduce flow.
    return STATIC_GENERATED_AT[:10]


def _run_ring1(root: Path, *, seed: int) -> tuple[list[dict], list[dict]]:
    """Run all Ring 1 generators.

    Returns (corpora_metadata, status_records). Each `corpora_metadata`
    entry is the metadata dict from the generator (with item_count,
    sha256, items[], etc.). Each status record carries the per-corpus
    pass/fail/skipped flag for the orchestrator's results.json.
    """

    corpora: list[dict] = []
    statuses: list[dict] = []
    for dir_name, module, default_count in RING1_GENERATORS:
        corpus_dir = root / "smabench" / "ring1" / dir_name
        try:
            metadata = module.generate(corpus_dir, count=default_count, seed=seed)
        except Exception as exc:  # noqa: BLE001 — surface exception class to status
            statuses.append(
                {
                    "name": dir_name,
                    "status": "failed",
                    "error_class": type(exc).__name__,
                    "error_message": str(exc),
                    "item_count": 0,
                }
            )
            continue
        # Trim the metadata before embedding into results.json — the
        # full per-item array can be hundreds of kB and lives on disk
        # at corpus.metadata.json; results.json just needs the summary.
        summary = {
            "name": metadata["name"],
            "item_count": metadata["item_count"],
            "sha256": metadata["sha256"],
            "source_policy": metadata["source_policy"],
            "publication_policy": metadata["publication_policy"],
            "seed": metadata["seed"],
            "requested_count": metadata["requested_count"],
            "generator": metadata.get("generator", {}),
        }
        corpora.append(summary)
        statuses.append(
            {
                "name": dir_name,
                "status": "passing",
                "item_count": metadata["item_count"],
                "sha256": metadata["sha256"],
            }
        )
    return corpora, statuses


def _build_results(root: Path, *, seed: int) -> dict[str, Any]:
    """Assemble the top-level results.json structure.

    The structure mirrors the Phase 0 placeholder so existing tests
    that key on `rings.ring1.corpora` and `rings.ring3.status` keep
    passing without modification.
    """

    corpora, ring1_statuses = _run_ring1(root, seed=seed)
    ring2 = run_ring2(root)

    ring1_status = "passing"
    if any(s["status"] == "failed" for s in ring1_statuses):
        ring1_status = "partial"
    if not ring1_statuses or all(s["status"] == "failed" for s in ring1_statuses):
        ring1_status = "failed"

    return {
        "tool_output_type": "smabench_results",
        "version": "v1.0",
        "generated_by": "aegisgraph-tier3-research",
        "generated_at": STATIC_GENERATED_AT,
        "safety_posture": "private_by_default",
        "rings": {
            "ring1": {
                "status": ring1_status,
                "corpora": corpora,
                "statuses": ring1_statuses,
                "generator_count": len(RING1_GENERATORS),
            },
            "ring2": ring2,
            "ring3": {
                "status": "authorization_placeholder",
                "policy": "requires written authorization before any dynamic target work",
            },
        },
    }


def _stable_hash(results: dict[str, Any]) -> str:
    """Hash the results dict, excluding fields that aren't byte-stable.

    Excluded keys: top-level `generated_at` (the calendar date is fine
    but the timestamp itself isn't load-bearing) and any nested
    `generated_at` carried in the embedded metadata (none today, but
    we strip defensively so future additions don't break the hash).
    """

    def _strip(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: _strip(v) for k, v in obj.items() if k != "generated_at"}
        if isinstance(obj, list):
            return [_strip(item) for item in obj]
        return obj

    cleansed = _strip(results)
    return sha256_bytes(canonical_json(cleansed))


def _previous_results(root: Path) -> dict[str, Any] | None:
    latest = root / "smabench" / "results" / "latest"
    candidate = latest / "results.json"
    if not candidate.is_file():
        return None
    try:
        with candidate.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return None


def _compute_delta(
    previous: dict[str, Any] | None, current: dict[str, Any]
) -> dict[str, Any]:
    """Compute the per-ring delta between the previous run and the current.

    Format:
      {
        "baseline": "<previous run's results sha or 'none'>",
        "previous_run_present": bool,
        "ring1": {
          "added_corpora": [...],
          "removed_corpora": [...],
          "changed_corpora": [{name, prev_sha, new_sha, item_count_delta}],
        },
        "ring2": { "status_change": "...", "score_delta": ... },
      }
    """

    if previous is None:
        return {
            "baseline": "none",
            "previous_run_present": False,
            "ring1": {"added_corpora": [], "removed_corpora": [], "changed_corpora": []},
            "ring2": {"status_change": None, "score_delta": 0.0},
        }

    prev_corpora = {c["name"]: c for c in previous.get("rings", {}).get("ring1", {}).get("corpora", [])}
    new_corpora = {c["name"]: c for c in current.get("rings", {}).get("ring1", {}).get("corpora", [])}

    added = sorted(set(new_corpora) - set(prev_corpora))
    removed = sorted(set(prev_corpora) - set(new_corpora))
    changed: list[dict[str, Any]] = []
    for name in sorted(set(new_corpora) & set(prev_corpora)):
        prev_sha = prev_corpora[name].get("sha256")
        new_sha = new_corpora[name].get("sha256")
        if prev_sha != new_sha:
            changed.append(
                {
                    "name": name,
                    "prev_sha": prev_sha,
                    "new_sha": new_sha,
                    "item_count_delta": (
                        int(new_corpora[name].get("item_count", 0))
                        - int(prev_corpora[name].get("item_count", 0))
                    ),
                }
            )

    prev_ring2 = previous.get("rings", {}).get("ring2", {})
    new_ring2 = current.get("rings", {}).get("ring2", {})
    prev_status = prev_ring2.get("status")
    new_status = new_ring2.get("status")
    status_change = (
        None if prev_status == new_status else {"from": prev_status, "to": new_status}
    )
    score_delta = round(
        float(new_ring2.get("aggregate_score") or 0.0)
        - float(prev_ring2.get("aggregate_score") or 0.0),
        3,
    )

    baseline = previous.get("repeatability", {}).get("hash") or _stable_hash(previous)
    return {
        "baseline": baseline,
        "previous_run_present": True,
        "ring1": {
            "added_corpora": added,
            "removed_corpora": removed,
            "changed_corpora": changed,
        },
        "ring2": {"status_change": status_change, "score_delta": score_delta},
    }


def _compute_recommendations(results: dict[str, Any]) -> list[dict[str, Any]]:
    """Emit recommendation cards for each Ring 2 target lacking passing
    validation tasks.

    The schema lives at `schema/recommendation.schema.json` and requires
    `id`, `version`, `category`, `graph_refs`, `evidence_refs`,
    `source_anchors`, `implementation_hint`, `expected_effect`,
    `residual_risk`, `effort_estimate`, `standards_mapping_caveat`, and
    `derived_from_finding` (or null).

    We emit one recommendation per Ring 2 target whose
    `validation_task_passing_ratio < 1.0` AND whose aggregate score is
    ≥0.7 (the SPEC's "high priority" cutoff). Below 0.7 we skip — the
    target hasn't yet earned a hardening recommendation.

    Recommendations are deterministic in the results dict so they're
    byte-stable across runs.
    """

    recs: list[dict[str, Any]] = []
    targets = results.get("rings", {}).get("ring2", {}).get("targets", []) or []
    for target in sorted(targets, key=lambda t: t["target"]):
        # The SPEC tag "high-priority node (score ≥0.7)" — we map this
        # to per-target aggregate score plus the existing extraction
        # score_vector totals being high. We use Ring 2's per-target
        # `score` for the gating check. Below 0.7 we skip.
        if float(target.get("score") or 0.0) < 0.7:
            continue
        if float(target.get("validation_task_passing_ratio") or 0.0) >= 1.0:
            continue
        target_key = target["target"]
        graph_path = target["graph_path"]
        rec = {
            "id": f"AG-REC-SMABENCH-{target_key.upper().replace('-', '_')}-MEDIA-001",
            "version": "v1.0",
            "category": "parser-hardening",
            "graph_refs": [graph_path] + sorted(target.get("referenced_node_ids", [])),
            "evidence_refs": [f"{graph_path}#records"],
            "source_anchors": [graph_path],
            "implementation_hint": (
                f"Promote at least one record under {target_key} "
                "from claim_state=validation_tasked to claim_state=reviewed by "
                "running the matched Ring 1 harness against the extraction graph "
                "and folding the resulting fact-vectors into the evidence record."
            ),
            "expected_effect": (
                "Closes the validation_task gap for the target's high-priority "
                "media-decode path; raises Ring 2 aggregate score by ≥0.1."
            ),
            "residual_risk": (
                "Ring 1 corpora are synthetic; passing them does not constitute "
                "a vulnerability claim against the live target. ReproChain ASAN "
                "results remain the authoritative validation for libwebp boundaries."
            ),
            "effort_estimate": "1-3 engineer days per target",
            "standards_mapping_caveat": (
                "Maps loosely to MASVS-CRYPTO and MASVS-CODE parser-hardening "
                "categories; not a formal standards conformance claim and not "
                "intended for SARIF/SBOM consumption without further review."
            ),
            "derived_from_finding": None,
        }
        recs.append(rec)
    return recs


def _render_dashboard(
    results: dict[str, Any],
    repeatability: dict[str, Any],
    delta: dict[str, Any],
    recommendations: list[dict[str, Any]],
) -> str:
    """Render a single-file static HTML dashboard.

    No live JS dependencies — embedded CSS plus a small, side-effect-free
    JSON island a reviewer can pop into devtools. Designed to render
    correctly in any modern browser opened from the local filesystem.
    """

    ring1 = results.get("rings", {}).get("ring1", {})
    ring2 = results.get("rings", {}).get("ring2", {})
    ring3 = results.get("rings", {}).get("ring3", {})

    def _esc(value: Any) -> str:
        text = "" if value is None else str(value)
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    rows_corpora = "\n".join(
        f"<tr><td>{_esc(c['name'])}</td>"
        f"<td>{_esc(c['item_count'])}</td>"
        f"<td>{_esc(c['source_policy'])}</td>"
        f"<td><code>{_esc(c['sha256'][:16])}…</code></td></tr>"
        for c in ring1.get("corpora", [])
    )
    rows_targets = "\n".join(
        f"<tr><td>{_esc(t['target'])}</td>"
        f"<td>{_esc(t['status'])}</td>"
        f"<td>{_esc(t['node_count'])}</td>"
        f"<td>{_esc(t['nodes_with_real_evidence_ratio'])}</td>"
        f"<td>{_esc(t['validation_task_passing_ratio'])}</td>"
        f"<td>{_esc(t['score'])}</td></tr>"
        for t in ring2.get("targets", [])
    )
    recs_html = "\n".join(
        f"<li><strong>{_esc(r['id'])}</strong> "
        f"<span class='cat'>{_esc(r['category'])}</span><br>"
        f"<small>{_esc(r['implementation_hint'])}</small></li>"
        for r in recommendations
    ) or "<li class='muted'>No recommendations emitted (no Ring 2 target met the score-≥0.7 gating threshold).</li>"

    delta_summary = (
        f"baseline={_esc(delta.get('baseline', 'none'))} · "
        f"corpora_changed={_esc(len(delta.get('ring1', {}).get('changed_corpora', [])))} · "
        f"ring2_score_delta={_esc(delta.get('ring2', {}).get('score_delta', 0.0))}"
    )

    json_island = json.dumps(
        {
            "results": results,
            "repeatability": repeatability,
            "delta": delta,
            "recommendations": recommendations,
        },
        sort_keys=True,
        indent=2,
    )

    repeat_state = "byte_identical" if repeatability.get("byte_identical") else "drift"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>AegisGraph SMABench Dashboard</title>
<style>
  :root {{
    --fg: #1a1a1a; --bg: #fafafa; --accent: #00766b; --muted: #888; --line: #e5e5e5;
  }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    margin: 2rem auto; max-width: 1100px; color: var(--fg); background: var(--bg);
    padding: 0 1.5rem; line-height: 1.5; }}
  h1 {{ border-bottom: 2px solid var(--accent); padding-bottom: 0.4rem; }}
  h2 {{ color: var(--accent); margin-top: 2rem; }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.5rem 0 1.5rem; }}
  th, td {{ border-bottom: 1px solid var(--line); padding: 0.5rem 0.6rem; text-align: left;
    vertical-align: top; }}
  th {{ background: #fff; font-weight: 600; font-size: 0.85rem;
    text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }}
  code {{ font-family: ui-monospace, Menlo, monospace; font-size: 0.85em;
    background: #fff; padding: 0.1rem 0.3rem; border: 1px solid var(--line);
    border-radius: 0.2rem; }}
  .pill {{ display: inline-block; padding: 0.15rem 0.55rem; border-radius: 1rem;
    font-size: 0.75rem; background: var(--accent); color: #fff; }}
  .pill-warn {{ background: #d97706; }}
  .pill-bad {{ background: #b91c1c; }}
  .muted {{ color: var(--muted); }}
  .cat {{ background: #eef; padding: 0.1rem 0.4rem; border-radius: 0.2rem;
    font-size: 0.75rem; color: #226; }}
  details summary {{ cursor: pointer; padding: 0.5rem 0; font-weight: 600; }}
  pre {{ background: #fff; border: 1px solid var(--line); padding: 1rem;
    overflow: auto; font-size: 0.78em; max-height: 480px; }}
  ul {{ padding-left: 1.4rem; }}
  ul li {{ margin: 0.4rem 0; }}
</style>
</head>
<body>
<h1>AegisGraph Tier 3 — SMABench Dashboard</h1>
<p class="muted">Generated {_esc(results.get("generated_at"))} · safety posture: {_esc(results.get("safety_posture"))}</p>

<h2>Ring 1 — Synthetic corpora <span class="pill {'' if ring1.get('status') == 'passing' else 'pill-warn'}">{_esc(ring1.get('status'))}</span></h2>
<table>
  <thead><tr><th>Corpus</th><th>Items</th><th>Source policy</th><th>SHA-256 (manifest)</th></tr></thead>
  <tbody>
{rows_corpora}
  </tbody>
</table>

<h2>Ring 2 — Real extraction consumer <span class="pill {'' if ring2.get('status', '').startswith('ring2_real') else 'pill-warn'}">{_esc(ring2.get('status'))}</span></h2>
<p class="muted">aggregate score {_esc(ring2.get('aggregate_score'))} · graphs present {_esc(ring2.get('graphs_present'))}/{_esc(ring2.get('graphs_expected'))}</p>
<table>
  <thead><tr><th>Target</th><th>Status</th><th>Nodes</th><th>Real-evidence ratio</th><th>Validation passing ratio</th><th>Score</th></tr></thead>
  <tbody>
{rows_targets}
  </tbody>
</table>

<h2>Ring 3 <span class="pill pill-warn">{_esc(ring3.get('status'))}</span></h2>
<p>{_esc(ring3.get('policy'))}</p>

<h2>Repeatability <span class="pill {'' if repeatability.get('byte_identical') else 'pill-bad'}">{repeat_state}</span></h2>
<p>iterations={_esc(repeatability.get('iterations'))} · hash <code>{_esc(repeatability.get('hash', '')[:32])}…</code></p>

<h2>Delta vs. previous run</h2>
<p class="muted">{delta_summary}</p>

<h2>Recommendations</h2>
<ul>
{recs_html}
</ul>

<h2>Raw JSON</h2>
<details>
  <summary>Show embedded results / repeatability / delta / recommendations</summary>
  <pre>{_esc(json_island)}</pre>
</details>

</body>
</html>
"""


def _set_latest_pointer(results_root: Path, dated: Path) -> str:
    """Make `results/latest` point at `results/<date>`.

    Prefer a real symlink. On platforms or filesystems where symlinks
    aren't available (Windows without dev mode, some CI containers),
    fall back to a sentinel file `latest.txt` plus copies of the four
    primary artifacts. Either way, downstream consumers can read
    `results/latest/results.json` and friends.

    Returns the strategy used: `"symlink"` or `"copy"`.
    """

    latest = results_root / "latest"
    # Best-effort cleanup of whatever was there before. We only delete
    # symlinks and known artifact filenames to avoid clobbering an
    # operator's manually-placed file.
    if latest.is_symlink() or latest.exists():
        if latest.is_symlink():
            latest.unlink()
        elif latest.is_dir():
            for child in latest.iterdir():
                if child.is_file() and child.name in {
                    "results.json",
                    "repeatability.json",
                    "delta.json",
                    "recommendations.json",
                    "dashboard.html",
                    "latest.txt",
                }:
                    child.unlink()
            try:
                latest.rmdir()
            except OSError:
                # Non-empty: leave any unknown contents intact.
                pass
    try:
        os.symlink(dated.name, latest, target_is_directory=True)
        return "symlink"
    except (OSError, NotImplementedError):
        # Fallback: copy the four primary files into a real directory.
        latest.mkdir(parents=True, exist_ok=True)
        for filename in ("results.json", "repeatability.json", "delta.json", "recommendations.json", "dashboard.html"):
            src = dated / filename
            if src.is_file():
                (latest / filename).write_bytes(src.read_bytes())
        (latest / "latest.txt").write_text(dated.name + "\n", encoding="utf-8")
        return "copy"


def run(root: Path, *, seed: int = DEFAULT_SEED) -> dict[str, Any]:
    """Run the full SMABench pipeline.

    Order of operations is load-bearing:
      1. Capture previous results before anything mutates.
      2. Run pipeline iteration 1.
      3. Run pipeline iteration 2 (against the SAME root — generators
         purge per-item files before re-emitting, so this is safe).
      4. Compare iteration 1 and iteration 2 hashes for byte-identity.
      5. Compute delta vs the previously-stored `latest/`.
      6. Emit recommendations + dashboard.
      7. Repoint `results/latest` -> `results/<date>`.

    Returns the iteration-1 results dict (which is identical to
    iteration-2 modulo `generated_at` if everything is byte-stable).
    """

    previous = _previous_results(root)

    iteration1 = _build_results(root, seed=seed)
    iteration2 = _build_results(root, seed=seed)

    h1 = _stable_hash(iteration1)
    h2 = _stable_hash(iteration2)
    repeatability = {
        "iterations": 2,
        "byte_identical": h1 == h2,
        "hash": h1,
        "secondary_hash": h2,
        "exclusions": ["generated_at"],
    }

    delta = _compute_delta(previous, iteration1)
    iteration1["repeatability"] = repeatability
    iteration1["delta"] = delta

    recommendations = _compute_recommendations(iteration1)

    # Emit artifacts under results/<date>/.
    results_root = root / "smabench" / "results"
    results_root.mkdir(parents=True, exist_ok=True)
    dated = results_root / _run_date()
    dated.mkdir(parents=True, exist_ok=True)

    write_json(dated / "results.json", iteration1)
    write_json(dated / "repeatability.json", repeatability)
    write_json(dated / "delta.json", delta)
    write_json(dated / "recommendations.json", recommendations)

    dashboard_html = _render_dashboard(iteration1, repeatability, delta, recommendations)
    (dated / "dashboard.html").write_text(dashboard_html, encoding="utf-8")

    pointer_strategy = _set_latest_pointer(results_root, dated)
    iteration1["results_pointer_strategy"] = pointer_strategy

    return iteration1
