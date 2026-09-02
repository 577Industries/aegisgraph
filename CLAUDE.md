# aegisgraph — instructions for agents

Never commit or push to `main` directly: branch from `origin/main`, open a PR, the founder merges. Streams rebase onto `stream/integration` (docs/operating-procedures.md §1/§6).

## CodeQL harness (`.github/workflows/invariants-ground-truth.yml`)

- The harness drives the raw CLI. Never add `codeql-action/init` — it stages a scan session that a manual `codeql database create` silently joins and finalises empty (exit 32). Install the bundle by direct download + `sha256sum -c`, put it on `$GITHUB_PATH`.
- Bump = new sha256 from the codeql-bundle release assets, updated together in the workflow, `devcontainer/Dockerfile` `ARG CODEQL_VERSION`, and `aegisgraph.tooling.REQUIRED_TOOLS`.
- `--build-mode=none` is Java-only. A Kotlin count of 0 under buildless is an extraction limit, not a bug; Kotlin needs the traced job (hosted ubuntu-24.04 ships Kotlin 2.4.10 ≤ the 2.26.4 extractor ceiling, Gradle, JDK 17, android-34 — no self-hosted runner needed).
- `_codeql_env()` scrubs `CODEQL_*`/`SEMMLE_*`/`JAVA_HOME*`/`LD_PRELOAD` on purpose for buildless. Do not simplify it; do not reuse it for traced builds.
- Every path-problem query imports `<FlowModule>::PathGraph`, never `DataFlow::PathGraph`.
- The buildless probe litters `gradlew`/`gradle`/`.gradle` into the fixture. Never commit it.

## Ground truth is a contract

- `GROUND_TRUTH_XFAIL` is strict: always measure; count == expected → fail loudly and delete the entry; count == recorded → xfail; anything else → fail and re-derive. Never turn an xfail into a skip.
- Fixtures under `tests/fixtures/demo-vulnerable-app/` are published ground truth. A fixture-line or expected-count change ships with an ADR in `docs/decision-log/` (founder decision 2026-09-01) and re-verifies INV-01 = 3 and INV-02 = 2.

Detail: tests/README.md · SPEC.md · extraction/BUILD_STATUS.md · docs/operating-procedures.md §§1/6/7/10 · docs/decision-log/.
