"""Reproduce the documented historical CVE/disclosure rediscoveries.

These cases are the credibility anchor of the regression run: each
asserts that python_urllib + whatwg_url_py produce a Disagreement on
the documented axis with the documented security tag.
"""

from __future__ import annotations

import pytest

from aegisgraph.polydiff import detect_disagreements, fact_vectors_for


# (input_url, expected_axis_subset, expected_tag_subset)
CASES = [
    pytest.param(
        "http://0177.0.0.1/",
        {"host", "host_is_loopback", "host_is_private_or_link_local"},
        {"ssrf-loopback-bypass"},
        id="CVE-2021-29921-IPv4-leading-zeroes",
    ),
    pytest.param(
        "http://2130706433/",
        {"host", "host_is_loopback"},
        {"ssrf-loopback-bypass"},
        id="CVE-2021-29921-class-decimal-IPv4",
    ),
    pytest.param(
        "http://127.1/",
        {"host", "host_is_loopback"},
        {"ssrf-loopback-bypass"},
        id="CVE-2021-29921-class-127.1-shorthand",
    ),
    pytest.param(
        "https://example%2ecom/",
        {"host_lowercased"},
        {"host-injection"},
        id="CVE-2022-37434-class-percent-in-host",
    ),
    pytest.param(
        r"https://example.com\@evil.example/",
        {"host_lowercased", "backslash_treated_as_slash"},
        {"path-confusion"},
        id="Snyk-2022-backslash-IE-legacy",
    ),
]


@pytest.mark.parametrize("url,expected_axes,expected_tags", CASES)
def test_documented_rediscovery(url: str, expected_axes: set[str], expected_tags: set[str]):
    vectors = fact_vectors_for("REPRO", url)
    assert vectors, "no parser wrappers dispatched"
    disagreements = detect_disagreements(vectors)
    assert disagreements, f"expected disagreement for {url}"
    observed_axes = {d.axis for d in disagreements}
    observed_tags = {t for d in disagreements for t in d.security_tags}

    missing_axes = expected_axes - observed_axes
    missing_tags = expected_tags - observed_tags
    assert not missing_axes, (
        f"input {url!r}: expected axes {expected_axes}, missing {missing_axes}, "
        f"observed {sorted(observed_axes)}"
    )
    assert not missing_tags, (
        f"input {url!r}: expected tags {expected_tags}, missing {missing_tags}, "
        f"observed {sorted(observed_tags)}"
    )
