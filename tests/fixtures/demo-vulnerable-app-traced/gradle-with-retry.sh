#!/usr/bin/env bash
# Traced-compile build command for tests/fixtures/demo-vulnerable-app/.
# Synthetic ground-truth fixture tooling. Not based on any real product code.
#
# Gradle fetches the Kotlin plugin from Maven Central, which occasionally
# answers 403 to GitHub-hosted runners (aegisgraph PR #9, run 33591582731).
# Three attempts with a pause turn that into a slow success instead of a
# failed measurement. The harness passes this file to `codeql database
# create --command`, which tokenises its argument on whitespace and does
# its own `$` expansion — hence a script, not a shell one-liner.
set -u
for attempt in 1 2 3; do
  # --rerun-tasks: a cached build/ would make Gradle skip the compilers and the
  # tracer would see no source at all (codeql exit 32); CI checkouts are clean,
  # repeated local runs are not.
  gradle --no-daemon --console=plain --rerun-tasks \
    -Pkotlin.compiler.execution.strategy=in-process compileKotlin compileJava && exit 0
  echo "gradle attempt ${attempt} failed; retrying in 30s" >&2
  sleep 30
done
exit 1
