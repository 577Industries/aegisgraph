PYTHON ?= python3
AEGISGRAPH := $(PYTHON) -m aegisgraph.cli

.PHONY: tooling tooling-strict test validate extract reprochain-build reprochain-run reprochain-map polydiff-regression smabench reproduce export-private export-public-sanitized traceability sanitize-check reprochain-fuzz polydiff-fuzz extract-deep

# tooling: probe every tool and write tooling-versions.json without enforcing
# minimum versions. Safe to run in any environment; useful diagnostic.
tooling:
	$(AEGISGRAPH) tooling

# tooling-strict: same probe + ENFORCE min versions from REQUIRED_TOOLS.
# Exit non-zero if any required tool is missing or below pin. Used as
# fail-closed gate at the top of `make reproduce`. Override locally with
# `AEGISGRAPH_STRICT_TOOLING=0` or by skipping this target only when the
# environment is intentionally partial.
tooling-strict:
	$(AEGISGRAPH) tooling --strict

# test: pytest unit + integration tests (excludes anything network-bound).
test:
	$(PYTHON) -m pytest

# validate: run the schema + safety + hash-chain validator across the repo.
# Output: validation-report.json. Status must be "pass" before exports.
validate:
	$(AEGISGRAPH) validate

# extract: phase-0 anchor-only extraction across the SMA target list.
extract:
	$(AEGISGRAPH) extract

# extract-deep: extract + MobSF + CodeQL deep stage (LONG; not in `reproduce`
# critical path). Requires Docker and MobSF image pulled. Reserved for
# pre-submission rebuilds; CI runs the lightweight `extract` instead.
extract-deep:
	$(AEGISGRAPH) extract --deep

# reprochain-build|run|map: scaffolded by the reprochain-proof stream.
reprochain-build:
	$(AEGISGRAPH) reprochain build

reprochain-run:
	$(AEGISGRAPH) reprochain run

reprochain-map:
	$(AEGISGRAPH) reprochain map

# reprochain-fuzz: 600s libFuzzer budget; LOCAL ONLY. Not in reproduce because
# fuzzing has no deterministic budget and cannot run on shared runners. Use
# this on a maintainer workstation while iterating on harness coverage.
reprochain-fuzz:
	$(AEGISGRAPH) reprochain fuzz --budget 600s

# polydiff-regression: deterministic regression run across the URL-parser
# fact-vector corpus. Always part of `reproduce`.
polydiff-regression:
	$(AEGISGRAPH) polydiff regression

# polydiff-fuzz: 60s differential fuzzing budget; LOCAL ONLY. Not in
# reproduce for the same reason as reprochain-fuzz.
polydiff-fuzz:
	$(AEGISGRAPH) polydiff fuzz --budget 60s

# smabench: deterministic ring1 corpus run. Part of `reproduce`.
smabench:
	$(AEGISGRAPH) smabench run

# traceability: emit reports/traceability_matrix.{json,md}. Implemented by
# the validator-export stream.
traceability:
	$(PYTHON) -m validator.cli traceability

# sanitize-check: scan exports/public-sanitized/ for forbidden patterns.
# Implemented by the validator-export stream. Used by GitHub Actions
# sanitize.yml as fail-closed gate before any human authorization step.
sanitize-check:
	$(PYTHON) -m validator.cli sanitize-check exports/public-sanitized

# reproduce: end-to-end deterministic chain. tooling-strict runs FIRST so
# missing pinned toolchain fails early and loud. extract-deep, *-fuzz are
# intentionally NOT here — `reproduce` must be reproducible on any pinned
# devcontainer in finite, bounded time.
reproduce: tooling-strict extract reprochain-build reprochain-run reprochain-map polydiff-regression smabench validate export-private
	@echo "AegisGraph Tier 3 private reproduction scaffold complete."

# export-private: bundle private DARPA/ASEMA submission candidate manifest.
# Always after `validate`.
export-private:
	$(AEGISGRAPH) export private

# export-public-sanitized: bundle the sanitized-candidate output. The
# release_authorized flag is FALSE unconditionally until the human gate
# (sanitize-check pass + AEGISGRAPH_RELEASE_AUTHORIZED=1) is wired by the
# validator-export stream. See docs/decision-log/0011-public-export-human-gate.md.
export-public-sanitized:
	$(AEGISGRAPH) export public-sanitized
