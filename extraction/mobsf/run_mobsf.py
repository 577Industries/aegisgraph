"""Offline MobSF runner for AegisGraph Tier 3 extraction.

Brings up the MobSF container with network features disabled, posts an
APK to its local API, fetches the JSON report, writes it to
`extraction/output/<target>/mobsf-results.json`, then tears down the
container.

The runner intentionally does NOT acquire the APK — that step belongs to
each target's build_db.sh (Signal: Gradle build) or to a manual F-Droid
download (Element X). See `extraction/mobsf/README.md` for the asymmetry.

Behavior when MobSF cannot run in the current environment:
  - docker not in PATH    -> emit `mobsf-results.json` with status="skipped"
                             reason="docker_unavailable"
  - apk file missing      -> emit ... reason="apk_missing"
  - container start fails -> emit ... reason="container_start_failed: <stderr>"
  - api timeout           -> emit ... reason="api_timeout"

We never silently no-op.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# httpx is in pyproject.toml dependencies; we use it for the MobSF HTTP API.
try:  # pragma: no cover - import guard, exercised in tests via try/except
    import httpx
except ImportError:  # pragma: no cover - httpx absence still emits a skipped record
    httpx = None  # type: ignore[assignment]


MOBSF_IMAGE_DEFAULT = "opensecurity/mobile-security-framework-mobsf:latest"
MOBSF_API_PORT_DEFAULT = 8000
MOBSF_BOOT_TIMEOUT_S = 60
MOBSF_REQUEST_TIMEOUT_S = 30


def _emit_skipped(out_path: Path, target_key: str, reason: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tool_output_type": "mobsf_results",
        "version": "v1.0",
        "target_key": target_key,
        "status": "skipped",
        "reason": reason,
        "image": MOBSF_IMAGE_DEFAULT,
        "report": None,
    }
    if extra:
        payload["extra"] = extra
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _emit_failed(out_path: Path, target_key: str, reason: str) -> dict[str, Any]:
    payload = {
        "tool_output_type": "mobsf_results",
        "version": "v1.0",
        "target_key": target_key,
        "status": "failed",
        "reason": reason,
        "image": MOBSF_IMAGE_DEFAULT,
        "report": None,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _start_container(image: str, port: int, container_name: str) -> tuple[bool, str]:
    """Start MobSF container. Returns (ok, stderr_or_id)."""
    cmd = [
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        container_name,
        "--network",
        "bridge",  # we still need a port mapping; offline-ness is enforced via env vars
        "--env",
        "MOBSF_DISABLE_NETWORK_FEATURES=1",
        "--env",
        "MOBSF_DISABLE_AUTHENTICATION=1",
        "-p",
        f"{port}:8000",
        image,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        return False, proc.stderr.strip() or proc.stdout.strip() or "unknown docker run error"
    return True, proc.stdout.strip()


def _stop_container(container_name: str) -> None:
    subprocess.run(
        ["docker", "stop", container_name],
        capture_output=True,
        text=True,
        timeout=30,
    )


def _wait_for_mobsf(port: int, timeout: int) -> bool:
    if httpx is None:
        return False
    url = f"http://127.0.0.1:{port}/api/v1/scans"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            resp = httpx.get(url, timeout=2.0)
            if resp.status_code in (200, 401, 403):
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1.0)
    return False


def _upload_and_scan(port: int, apk_path: Path) -> dict[str, Any] | None:
    if httpx is None:
        return None
    base = f"http://127.0.0.1:{port}"
    try:
        with apk_path.open("rb") as fh:
            files = {"file": (apk_path.name, fh, "application/octet-stream")}
            up = httpx.post(f"{base}/api/v1/upload", files=files, timeout=MOBSF_REQUEST_TIMEOUT_S)
        if up.status_code != 200:
            return {"error": f"upload status {up.status_code}", "body": up.text[:512]}
        meta = up.json()
        scan_payload = {"hash": meta.get("hash"), "scan_type": meta.get("scan_type", "apk"), "file_name": meta.get("file_name")}
        sc = httpx.post(f"{base}/api/v1/scan", data=scan_payload, timeout=120)
        if sc.status_code != 200:
            return {"error": f"scan status {sc.status_code}", "body": sc.text[:512]}
        report = sc.json()
        return report
    except httpx.HTTPError as exc:
        return {"error": f"http error: {exc}"}


def run_mobsf(
    target_key: str,
    apk_path: Path | None,
    out_path: Path,
    image: str = MOBSF_IMAGE_DEFAULT,
    port: int = MOBSF_API_PORT_DEFAULT,
) -> dict[str, Any]:
    """Run MobSF against `apk_path` and write the report to `out_path`.

    Always writes a JSON file with at least {"status": ...}; never silently
    no-ops.
    """
    if not _docker_available():
        return _emit_skipped(out_path, target_key, "docker_unavailable")

    if httpx is None:
        return _emit_skipped(out_path, target_key, "httpx_unavailable")

    if apk_path is None or not apk_path.is_file():
        return _emit_skipped(
            out_path,
            target_key,
            "apk_missing",
            extra={"expected_path": str(apk_path) if apk_path else None},
        )

    container_name = f"aegisgraph-mobsf-{target_key}-{os.getpid()}"
    ok, msg = _start_container(image, port, container_name)
    if not ok:
        return _emit_skipped(out_path, target_key, f"container_start_failed: {msg}")

    try:
        if not _wait_for_mobsf(port, MOBSF_BOOT_TIMEOUT_S):
            return _emit_skipped(out_path, target_key, "mobsf_boot_timeout")

        report = _upload_and_scan(port, apk_path)
        if report is None or (isinstance(report, dict) and "error" in report):
            err = report.get("error") if isinstance(report, dict) else "no report"
            return _emit_failed(out_path, target_key, f"scan_failed: {err}")

        payload = {
            "tool_output_type": "mobsf_results",
            "version": "v1.0",
            "target_key": target_key,
            "status": "ran",
            "image": image,
            "apk_path": str(apk_path),
            "report": report,
        }
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return payload
    finally:
        _stop_container(container_name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_mobsf")
    parser.add_argument("target_key", choices=["signal", "element-x"])
    parser.add_argument(
        "--apk",
        type=Path,
        default=None,
        help="Path to APK file. Required for status='ran'; absent path emits status='skipped'.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Destination JSON path (extraction/output/<target>/mobsf-results.json).",
    )
    parser.add_argument("--image", default=MOBSF_IMAGE_DEFAULT)
    parser.add_argument("--port", type=int, default=MOBSF_API_PORT_DEFAULT)
    args = parser.parse_args(argv)

    result = run_mobsf(args.target_key, args.apk, args.output, image=args.image, port=args.port)
    print(json.dumps({"status": result["status"], "reason": result.get("reason")}, sort_keys=True))
    return 0 if result["status"] == "ran" else 0  # skipped/failed are non-fatal in extraction pipeline


if __name__ == "__main__":
    sys.exit(main())
