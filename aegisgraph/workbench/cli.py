"""`aegisgraph workbench` subparser — list, show, promote, packet.

This module is registered by `aegisgraph.cli.build_parser`. Each sub-
subcommand has its own command function:

  - cmd_workbench_list     -> list_findings + table/JSON render
  - cmd_workbench_show     -> show_finding + Markdown/JSON render
  - cmd_workbench_promote  -> additive supersedes record write
                              (validates via aegisgraph.claims.transition_allowed)
  - cmd_workbench_packet   -> packet_export.export_packet

The promote path is the only mutating operation; it appends a new
record to a per-engine workbench log under
``aegisgraph/workbench/promotions/<ISO_DATE>/<record_id>.json``.
Original records are *never* edited (ADR-0010 additive). The new
record carries:

  - id: <orig_id>+<new_state>  (e.g. AG-EV-...-001+anchored)
  - claim_state: <new>
  - supersedes: <orig_id>
  - hash_chain.previous_hash: <orig record_hash>
  - record_hash recomputed via aegisgraph.hashchain.attach_hash_chain
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..claims import canonical_claim_state, transition_allowed
from ..hashchain import attach_hash_chain
from ..io import repo_root
from .filters import FilterSpec, filters_from_namespace
from .finding_detail import render_markdown, show_finding
from .finding_list import list_findings, render_table
from .packet_export import export_packet
from .registry import find_record


def _root_from_args(args: argparse.Namespace) -> Path:
    raw = getattr(args, "root", None)
    return Path(raw) if raw else repo_root()


def cmd_workbench_list(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    filters = filters_from_namespace(args)
    rows = list_findings(root, filters)
    output_rows = [
        {k: v for k, v in row.items() if k != "_record"} for row in rows
    ]
    fmt = getattr(args, "format", "table")
    if fmt == "json":
        print(json.dumps(output_rows, indent=2, sort_keys=True, default=_json_default))
        return 0
    print(render_table(rows), end="")
    return 0


def cmd_workbench_show(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    record_id = args.record_id
    envelope = show_finding(root, record_id)
    fmt = getattr(args, "format", "markdown")
    if envelope.get("not_found"):
        print(f"record not found: {record_id}", file=sys.stderr)
        return 1
    if fmt == "json":
        # Drop the embedded `record` haystack into a top-level field so
        # the JSON view mirrors the Markdown view's hierarchy.
        print(json.dumps(envelope, indent=2, sort_keys=True, default=_json_default))
        return 0
    print(render_markdown(envelope))
    return 0


def cmd_workbench_promote(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    record_id = args.record_id
    target_state = args.to
    envelope = show_finding(root, record_id)
    if envelope.get("not_found"):
        print(f"record not found: {record_id}", file=sys.stderr)
        return 1
    prior = envelope.get("record") or {}
    prior_state = envelope.get("claim_state")
    try:
        canonical_prior = canonical_claim_state(prior_state)
        canonical_next = canonical_claim_state(target_state)
    except ValueError as exc:
        print(f"invalid claim state: {exc}", file=sys.stderr)
        return 2
    transition = transition_allowed(canonical_prior, canonical_next)
    if not transition.valid:
        print(
            f"transition refused: {canonical_prior} -> {canonical_next}: {transition.reason}",
            file=sys.stderr,
        )
        return 2

    new_record = _build_promoted_record(
        prior=prior,
        prior_record_id=record_id,
        prior_record_hash=envelope.get("record_hash") or "",
        target_state=canonical_next,
        actor=getattr(args, "actor", None),
        justification=getattr(args, "justification", None),
    )

    out_path = _promotion_path(root, new_record["id"])
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(new_record, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps({
        "new_record_id": new_record["id"],
        "claim_state": new_record["claim_state"],
        "supersedes": new_record["supersedes"],
        "record_hash": new_record["hash_chain"]["record_hash"],
        "path": str(out_path.relative_to(root)),
    }, indent=2, sort_keys=True))
    return 0


def cmd_workbench_packet(args: argparse.Namespace) -> int:
    root = _root_from_args(args)
    top_n = int(getattr(args, "top", 10))
    out_dir_raw = getattr(args, "out", None)
    out_dir = Path(out_dir_raw) if out_dir_raw else None
    if out_dir is not None and not out_dir.is_absolute():
        out_dir = root / out_dir
    filter_spec = FilterSpec.parse(getattr(args, "filter", None))
    manifest = export_packet(root, top_n=top_n, out_dir=out_dir, filter_spec=filter_spec)
    print(json.dumps({
        "iso_date": manifest["iso_date"],
        "findings_emitted": len(manifest["findings"]),
        "artifacts": len(manifest["artifacts"]),
        "sanitize_check": manifest["sanitize_check"]["status"],
    }, indent=2, sort_keys=True))
    return 0 if manifest["sanitize_check"]["status"] in {"pass", "skipped"} else 1


def _build_promoted_record(
    *,
    prior: dict[str, Any],
    prior_record_id: str,
    prior_record_hash: str,
    target_state: str,
    actor: str | None,
    justification: str | None,
) -> dict[str, Any]:
    """Build a new AG-* record that supersedes the prior.

    The promoted record is the *minimum surface* needed for the
    workbench log: claim_state, supersedes, provenance, an empty
    hash_chain that will be filled in via attach_hash_chain. We
    intentionally do NOT copy the prior's payload-bearing fields
    (score_vector, nodes, edges, evidence_refs, etc.) — the prior
    record remains the authoritative carrier of that detail. The
    promotion record is a *claim-state delta* envelope that points
    back to its predecessor via `supersedes`.

    This shape is consistent with ADR-0010 (additive only): the prior
    record is immutable; the new record adds the state transition.
    """
    new_id = _promoted_id(prior_record_id, target_state)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    record: dict[str, Any] = {
        "id": new_id,
        "version": "v1.0",
        "kind": "workbench_promotion",
        "claim_state": target_state,
        "supersedes": prior_record_id,
        "promoted_at": now,
        "promoted_by": actor or "workbench_anonymous",
        "justification": justification or "(none provided)",
        "prior_record_hash": prior_record_hash,
        "provenance": {
            "generated_by": "aegisgraph-workbench",
            "generated_at": now,
            "source": "workbench_promote",
            "private_by_default": True,
        },
    }
    return attach_hash_chain(record, previous_hash=prior_record_hash or None)


def _promoted_id(prior_id: str, target_state: str) -> str:
    return f"{prior_id}+{target_state.upper()}"


def _promotion_path(root: Path, new_id: str) -> Path:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    safe = new_id.replace("/", "_")
    return root / "aegisgraph" / "workbench" / "promotions" / today / f"{safe}.json"


def _json_default(value: Any) -> Any:
    if isinstance(value, (Path,)):
        return str(value)
    return str(value)


def register_subparser(
    subparsers: argparse._SubParsersAction[Any],
) -> argparse.ArgumentParser:
    """Mount the `workbench` subparser onto an existing aegisgraph CLI tree."""
    parser = subparsers.add_parser(
        "workbench",
        help="reviewer workbench: list / show / promote / packet (CLI-only)",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="repo root override (default: aegisgraph.io.repo_root())",
    )
    sub = parser.add_subparsers(dest="workbench_command", required=True)

    list_p = sub.add_parser("list", help="list findings filtered by engine/target/claim_state")
    list_p.add_argument("--engine", default=None, help="filter by engine bucket (e.g. polydiff)")
    list_p.add_argument("--target", default=None, help="filter by target name substring")
    list_p.add_argument("--claim-state", dest="claim_state", default=None, help="filter by claim_state")
    list_p.add_argument("--format", choices=("table", "json"), default="table")
    list_p.set_defaults(func=cmd_workbench_list)

    show_p = sub.add_parser("show", help="show a single record (resolves evidence_refs + supersedes chain)")
    show_p.add_argument("record_id", help="AG-* record id")
    show_p.add_argument("--format", choices=("markdown", "json"), default="markdown")
    show_p.set_defaults(func=cmd_workbench_show)

    promote_p = sub.add_parser(
        "promote",
        help="create a NEW record that supersedes RECORD_ID at new claim_state (additive; ADR-0010)",
    )
    promote_p.add_argument("record_id", help="AG-* record id to promote")
    promote_p.add_argument("--to", required=True, help="target claim_state")
    promote_p.add_argument("--actor", default=None, help="reviewer email (recorded in promoted_by)")
    promote_p.add_argument("--justification", default=None, help="free-text justification")
    promote_p.set_defaults(func=cmd_workbench_promote)

    packet_p = sub.add_parser("packet", help="export the reviewer packet")
    packet_p.add_argument("--top", type=int, default=10, help="top-N findings by score_total")
    packet_p.add_argument("--out", default=None, help="output directory (default: exports/reviewer-packet)")
    packet_p.add_argument(
        "--filter",
        default=None,
        help="filter expression: key=value pairs separated by ',' (keys: engine, target, claim_state)",
    )
    packet_p.set_defaults(func=cmd_workbench_packet)

    return parser
