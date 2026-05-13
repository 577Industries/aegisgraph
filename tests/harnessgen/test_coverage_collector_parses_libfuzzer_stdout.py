"""coverage_collector.parse_libfuzzer_stdout extracts a summary record from
libFuzzer's stdout.

libFuzzer prints periodic stats lines that look like:

    #1234	NEW    cov: 152 ft: 290 corp: 47/1024b lim: 4096 exec/s: 1234 rss: 102Mb
    #5678	pulse  cov: 152 ft: 290 corp: 47/1024b lim: 4096 exec/s: 1500 rss: 102Mb

And on crash:

    SUMMARY: AddressSanitizer: heap-buffer-overflow

We extract the *last* known cov/ft/corp/execs values plus any SUMMARY line
into a `CoverageSummary` dict. No raw stack traces are retained — the
SUMMARY's top-level category string is the only bug signal we keep.
"""

from __future__ import annotations

from aegisgraph.harnessgen.runners.coverage_collector import (
    CoverageSummary,
    parse_libfuzzer_stdout,
)


SAMPLE_CLEAN = """\
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 1234567890
#1	INITED cov: 100 ft: 200 corp: 1/1b lim: 4 exec/s: 0 rss: 80Mb
#1024	pulse  cov: 152 ft: 290 corp: 47/1024b lim: 4096 exec/s: 1234 rss: 102Mb
Done 10000 runs in 60 second(s)
"""

SAMPLE_CRASH = """\
INFO: Running with entropic power schedule (0xFF, 100).
#1024	pulse  cov: 152 ft: 290 corp: 47/1024b lim: 4096 exec/s: 1234 rss: 102Mb
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef
SUMMARY: AddressSanitizer: heap-buffer-overflow
"""


def test_parse_clean_run_returns_summary() -> None:
    summary = parse_libfuzzer_stdout(SAMPLE_CLEAN)
    assert isinstance(summary, dict)
    assert summary["coverage_features"] == 152
    assert summary["coverage_edges"] == 290
    assert summary["corpus_size"] == 47
    assert summary["exec_per_sec"] == 1234


def test_parse_clean_run_has_no_crash() -> None:
    summary = parse_libfuzzer_stdout(SAMPLE_CLEAN)
    assert summary.get("crash_summary") is None


def test_parse_crash_extracts_top_level_category() -> None:
    summary = parse_libfuzzer_stdout(SAMPLE_CRASH)
    # crash_summary is the top-level category only — NO addresses, NO frames.
    assert summary["crash_summary"] is not None
    assert "heap-buffer-overflow" in summary["crash_summary"]
    # The hex address must NOT leak into the summary.
    assert "0xdeadbeef" not in summary["crash_summary"]


def test_parse_crash_uses_summary_line_not_error_line() -> None:
    """We parse the canonical `SUMMARY:` line, not the verbose ==pid==ERROR
    line. The ERROR line carries an address and is intentionally dropped."""
    summary = parse_libfuzzer_stdout(SAMPLE_CRASH)
    assert summary["crash_summary"].startswith("AddressSanitizer")


def test_parse_empty_returns_zero_defaults() -> None:
    summary = parse_libfuzzer_stdout("")
    assert summary["coverage_features"] == 0
    assert summary["coverage_edges"] == 0
    assert summary["corpus_size"] == 0
    assert summary["exec_per_sec"] == 0


def test_summary_is_serializable() -> None:
    """The summary will be embedded in evidence records, so every value
    must be JSON-serializable (no objects, no bytes, no sets)."""
    import json

    for sample in (SAMPLE_CLEAN, SAMPLE_CRASH):
        summary = parse_libfuzzer_stdout(sample)
        json.dumps(summary)  # raises if non-serializable
