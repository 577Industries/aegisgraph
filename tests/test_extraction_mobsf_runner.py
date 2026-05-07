"""MobSF runner: skipped paths.

We cannot exercise the docker-up path in unit tests, but we can lock the
behavior when:
  - docker is not available
  - apk file is missing

Both paths must emit a JSON file with status='skipped' and a reason — never
silently no-op.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from extraction.mobsf.run_mobsf import run_mobsf


def test_skipped_when_apk_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "mobsf-results.json"
    # Ensure docker_available passes so we hit the apk-missing branch first.
    # We monkeypatch `_docker_available` -> True.
    import extraction.mobsf.run_mobsf as mod

    monkeypatch.setattr(mod, "_docker_available", lambda: True)

    result = run_mobsf("signal", apk_path=tmp_path / "absent.apk", out_path=out)
    assert result["status"] == "skipped"
    assert result["reason"] == "apk_missing"
    assert out.is_file()
    on_disk = json.loads(out.read_text())
    assert on_disk["status"] == "skipped"


def test_skipped_when_docker_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    out = tmp_path / "mobsf-results.json"
    import extraction.mobsf.run_mobsf as mod

    monkeypatch.setattr(mod, "_docker_available", lambda: False)
    result = run_mobsf("signal", apk_path=None, out_path=out)
    assert result["status"] == "skipped"
    assert result["reason"] == "docker_unavailable"
    assert out.is_file()
