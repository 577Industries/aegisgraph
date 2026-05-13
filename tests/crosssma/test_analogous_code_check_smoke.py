"""analogous_code_check smoke test.

The query takes a structural-signature fingerprint and a target, and
returns whether the target's graph data plausibly hosts the same
pattern. v0 implementation is path-class + family based (no AST
match yet — that lands in a later milestone). The smoke test pins
the shape of the return value so callers can reason about it.
"""

from __future__ import annotations

from aegisgraph.crosssma.pattern_extractor import PatternFingerprint
from aegisgraph.crosssma.queries.analogous_code_check import (
    AnalogousCodeResult,
    check_analogous_code,
)
from aegisgraph.crosssma.target_registry import Target


def _mock_fp(pattern_type: str = "parser_disagreement", family: str = "url") -> PatternFingerprint:
    return PatternFingerprint(
        pattern_type=pattern_type,
        family=family,
        axis="backslash_handling",
        implementations=("java.net.URI", "whatwg-url"),
        canonical_input='{"axis":"backslash_handling"...}',
        structural_signature="a" * 64,
    )


def _mock_target_with(path_classes: tuple[str, ...]) -> Target:
    return Target(
        target_id="mock-target",
        name="Mock",
        repo_url="https://example.invalid",
        commit="0000000",
        verified=False,
        path_classes=path_classes,
        dependency_snapshot=tuple(),
    )


def test_returns_analogous_code_result() -> None:
    fp = _mock_fp()
    target = _mock_target_with(("link_preview", "inbound_message"))
    result = check_analogous_code(target, fp)
    assert isinstance(result, AnalogousCodeResult)
    # Either True or False; the shape is what matters at v0.
    assert isinstance(result.matches, bool)


def test_url_pattern_matches_link_preview_path_class() -> None:
    """A URL parser_disagreement is plausibly present in any target with
    a link_preview path class. This is a coarse heuristic, but it's
    the v0 contract."""
    fp = _mock_fp()
    target = _mock_target_with(("link_preview",))
    result = check_analogous_code(target, fp)
    assert result.matches is True


def test_url_pattern_does_not_match_target_without_relevant_path_class() -> None:
    fp = _mock_fp()
    target = _mock_target_with(("crypto_key_lifecycle",))
    result = check_analogous_code(target, fp)
    assert result.matches is False


def test_image_pattern_matches_media_decode_path_class() -> None:
    fp = _mock_fp(family="image")
    target = _mock_target_with(("media_decode",))
    result = check_analogous_code(target, fp)
    assert result.matches is True
