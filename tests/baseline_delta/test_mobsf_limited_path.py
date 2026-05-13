"""When MobSF cannot run because no APK is available, the runner MUST
write MOBSF-LIMITED.md transparently. No fabricated findings.

Required fields in MOBSF-LIMITED.md (markdown body, but with structured
front matter / sections the renderer can read back):

  * target_id
  * target_repo + commit
  * reason  (apk_missing | binary_missing)
  * timestamp (STATIC_GENERATED_AT for determinism)
  * policy_note (explaining anchor-only policy)

The runner returns the same `apk_missing` envelope it returns when the
binary is present but APK is not.
"""

from __future__ import annotations

from pathlib import Path

from aegisgraph.baseline_delta.runner import (
    MOBSF_LIMITED_FILENAME,
    run_mobsf_alone,
    write_mobsf_limited_md,
)


def _make_target() -> dict:
    return {
        "target_key": "signal",
        "target_id": "signal_android@1043851",
        "name": "Signal Android",
        "repo_url": "https://github.com/signalapp/Signal-Android",
        "commit": "1043851",
        "source_root": "/tmp/none",
        "apk_path": None,
    }


def test_mobsf_limited_md_filename_constant_is_stable() -> None:
    """The filename is part of the public artifact tree shape — lock it."""
    assert MOBSF_LIMITED_FILENAME == "MOBSF-LIMITED.md"


def test_write_mobsf_limited_md_emits_required_fields(tmp_path: Path) -> None:
    target = _make_target()
    md_path = write_mobsf_limited_md(
        output_dir=tmp_path,
        target=target,
        reason="apk_missing",
    )

    assert md_path.name == MOBSF_LIMITED_FILENAME
    assert md_path.is_file()
    text = md_path.read_text(encoding="utf-8")

    # Required content sections / fields:
    assert "signal_android@1043851" in text
    assert "https://github.com/signalapp/Signal-Android" in text
    assert "1043851" in text
    assert "apk_missing" in text
    # Anchor-only policy note must be present so reviewers see why the
    # APK is intentionally absent in this anchor-only research repo.
    assert "anchor-only" in text.lower() or "anchor only" in text.lower()
    # Determinism: STATIC_GENERATED_AT-based timestamp present.
    assert "2026-05-05" in text


def test_run_mobsf_alone_when_apk_absent_writes_mobsf_limited_and_no_findings(tmp_path: Path) -> None:
    target = _make_target()
    out_dir = tmp_path / "signal_android"

    def _which_docker_only(binary: str) -> str | None:
        return "/usr/bin/docker" if binary == "docker" else None

    result = run_mobsf_alone(
        target=target,
        output_dir=out_dir,
        which=_which_docker_only,
    )

    assert result["status"] == "apk_missing"
    assert result["findings_count"] == 0
    assert result["mobsf_limited_md"] is not None

    limited_path = Path(result["mobsf_limited_md"])
    assert limited_path.is_file()
    assert limited_path.name == MOBSF_LIMITED_FILENAME

    # No mobsf-findings.json must be written when APK is absent — we
    # do NOT fabricate findings.
    assert not (out_dir / "mobsf-findings.json").exists()


def test_run_mobsf_alone_does_not_fabricate_findings(tmp_path: Path) -> None:
    """Defense-in-depth: even when the runner could run docker, missing
    APK MUST NOT produce a mobsf-findings.json file with any contents.
    """
    target = _make_target()
    out_dir = tmp_path / "out"

    def _which_docker_only(binary: str) -> str | None:
        return "/usr/bin/docker" if binary == "docker" else None

    run_mobsf_alone(
        target=target,
        output_dir=out_dir,
        which=_which_docker_only,
    )

    # Either the file doesn't exist OR (if a stub envelope was written)
    # it must declare status apk_missing and have zero findings.
    findings_path = out_dir / "mobsf-findings.json"
    if findings_path.exists():
        import json

        payload = json.loads(findings_path.read_text(encoding="utf-8"))
        assert payload.get("status") in {"apk_missing", "binary_missing"}
        assert payload.get("findings_count", 0) == 0
        # No "findings" array with non-empty contents.
        assert payload.get("findings", []) == []
