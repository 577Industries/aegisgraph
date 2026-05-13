"""URL family wrapper-dispatch logic.

Discovers available URL parser wrappers (python_urllib, whatwg_url_py,
java-net-uri, okhttp_httpurl, go-neturl, rust-url, libcurl) via the
on-disk PARSER_STATUS.json manifest. Only the Python-native wrappers
are dispatched from this orchestrator; the rest ship with their own
test_basic.sh runners and require the devcontainer toolchain.

Extracted from the monolithic `aegisgraph/polydiff.py` as part of
T-M2.3 (PolyDiff URL family refactor). Pure refactor — no behavior
change.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from ...core.factvector import run_wrapper


PARSER_STATUS_FILENAME = "PARSER_STATUS.json"


def _parser_status_path(root: Path) -> Path:
    return root / "polydiff" / "parsers" / PARSER_STATUS_FILENAME


def _source_root() -> Path:
    """Source-tree root (the repo this module ships from).

    Used as a fallback when `run_regression(tmp_path)` is invoked with a
    tmp dir that doesn't have a parsers/ tree. Tests like
    test_e2e_reproduce do exactly this — they want the regression to
    produce real records inside the temp dir without copying the
    parsers/ tree there.
    """
    # aegisgraph/polydiff/families/url/profiles.py -> parents[4] = repo root
    return Path(__file__).resolve().parents[4]


def load_parser_status(root: Path) -> dict[str, dict[str, Any]]:
    p = _parser_status_path(root)
    if not p.exists():
        # Fall back to the source tree so callers that pass a tmp_path
        # (e.g. integration tests) still see the canonical parser set.
        p = _parser_status_path(_source_root())
        if not p.exists():
            return {}
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh).get("wrappers", {})


def _wrapper_command(profile: str, status_entry: dict[str, Any], root: Path) -> list[str] | None:
    """Return the argv to dispatch a wrapper, or None if unrunnable here."""
    if status_entry.get("status") != "built":
        return None
    directory = status_entry.get("directory")
    if not directory:
        return None
    abs_dir = root / directory
    if not abs_dir.exists():
        # Fall back to the source root (the worktree this module ships
        # from). Lets `run_regression(tmp_path)` work without having to
        # copy the entire parsers/ tree into the temp dir.
        abs_dir = _source_root() / directory
        if not abs_dir.exists():
            return None

    # We only auto-dispatch the Python wrappers in the orchestrator. The
    # rest are buildable but require the toolchain inside the sandboxed
    # devcontainer; they ship with their own test_basic.sh runners.
    if profile in ("python_urllib", "whatwg_url_py"):
        return [sys.executable, str(abs_dir / "wrapper.py")]
    return None


def fact_vectors_for(input_id: str, url: str, root: Path | None = None) -> list[dict[str, Any]]:
    """Run every available wrapper against `url` and return the fact vectors.

    `root` defaults to the repo root. Used by the tests for an
    in-process equivalent of `run_regression`.
    """
    from polydiff.factvec.normalize import normalize  # local import to avoid cycle

    if root is None:
        from aegisgraph.io import repo_root
        root = repo_root()

    status = load_parser_status(root)
    vectors: list[dict[str, Any]] = []
    for profile, entry in sorted(status.items()):
        cmd = _wrapper_command(profile, entry, root)
        if cmd is None:
            # Skip unrunnable wrappers; the regression report records this.
            continue
        envelope = run_wrapper(profile, cmd, input_id, url)
        vectors.append(normalize(envelope, parser_profile=profile))
    return vectors


__all__ = [
    "PARSER_STATUS_FILENAME",
    "load_parser_status",
    "fact_vectors_for",
    "_wrapper_command",
    "_parser_status_path",
    "_source_root",
]
