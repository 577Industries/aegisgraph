"""Parse libFuzzer stdout into a coverage summary record.

libFuzzer emits periodic status lines like:

    #1234	NEW    cov: 152 ft: 290 corp: 47/1024b lim: 4096 exec/s: 1234 rss: 102Mb

and on crash:

    ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
    SUMMARY: AddressSanitizer: heap-buffer-overflow

We extract the LAST observed cov/ft/corp/execs values plus any SUMMARY
line into a CoverageSummary dict. We intentionally do NOT keep:

  * the ==pid==ERROR line — it contains an address
  * the verbose stack frames — they would leak source-tree internals
  * the raw input bytes — not present in stdout anyway, but defense-in-depth

Only the SUMMARY's top-level sanitizer category is retained, and that is
all that feeds the crash_class field of an AG-CRASH-* record.
"""

from __future__ import annotations

import re
from typing import TypedDict


# Match the libFuzzer stats line. Anchored on `#N\t<state>` then keyed
# k: v pairs. Newline-anchored to skip the same line twice.
_STATS_RE = re.compile(
    r"cov:\s*(?P<cov>\d+)\s+"
    r"ft:\s*(?P<ft>\d+)\s+"
    r"corp:\s*(?P<corp>\d+)/[\d\w]+\s+"
    r"lim:\s*\d+\s+"
    r"exec/s:\s*(?P<exec>\d+)"
)

# `SUMMARY: <Sanitizer>: <category>` — we take the post-`SUMMARY: ` portion
# UP TO the first ` on address ` or end-of-line so we don't capture the
# leaked address.
_SUMMARY_RE = re.compile(
    r"^SUMMARY:\s+(?P<summary>[^\n]+?)(?:\s+on address\s+0x[0-9a-fA-F]+)?\s*$",
    re.MULTILINE,
)


class CoverageSummary(TypedDict, total=False):
    """A subset of libFuzzer's stats that we retain.

    `crash_summary` is None on clean runs; on crashes it's the top-level
    sanitizer category only (no address, no frame names).
    """

    coverage_features: int  # NEW edges discovered (cov:)
    coverage_edges: int  # feature counter (ft:)
    corpus_size: int  # corpus entry count
    exec_per_sec: int  # most-recent exec/s reading
    crash_summary: str | None  # top-level sanitizer category or None


def parse_libfuzzer_stdout(text: str) -> CoverageSummary:
    """Return a CoverageSummary built from libFuzzer's stdout `text`.

    Returns sane zero defaults if `text` is empty or contains no parseable
    stats — the caller treats this as "ran but didn't make progress".
    """
    summary: CoverageSummary = {
        "coverage_features": 0,
        "coverage_edges": 0,
        "corpus_size": 0,
        "exec_per_sec": 0,
        "crash_summary": None,
    }

    last_match: re.Match[str] | None = None
    for match in _STATS_RE.finditer(text):
        last_match = match
    if last_match is not None:
        summary["coverage_features"] = int(last_match.group("cov"))
        summary["coverage_edges"] = int(last_match.group("ft"))
        summary["corpus_size"] = int(last_match.group("corp"))
        summary["exec_per_sec"] = int(last_match.group("exec"))

    summary_match = _SUMMARY_RE.search(text)
    if summary_match is not None:
        summary["crash_summary"] = summary_match.group("summary").strip()

    return summary


__all__ = ["CoverageSummary", "parse_libfuzzer_stdout"]
