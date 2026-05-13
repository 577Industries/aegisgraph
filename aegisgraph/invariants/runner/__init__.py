"""InvariantCheck runners.

Three modules:

  * `codeql_runner` — invokes the `codeql` CLI as a subprocess against a
    pre-built CodeQL database; emits SARIF.
  * `semgrep_runner` — invokes the `semgrep` CLI as a subprocess against
    a source tree; emits SARIF.
  * `sarif_consolidator` — converts SARIF results into AG-IV-* evidence
    records validating against schema/invariant-violation.schema.json.

The CLI runners are GUARDED by `shutil.which()` checks; if the binary is
absent, `run_codeql` / `run_semgrep` return a `tool_run_status` block with
`status="skipped_pending_toolchain"` instead of raising. Tests use this
guard with `pytest.mark.skipif(not shutil.which(...))` for the
live-execution path; everything else mocks the SARIF input.
"""

from __future__ import annotations

__all__: list[str] = []
