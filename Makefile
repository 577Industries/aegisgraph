PYTHON ?= python3
AEGISGRAPH := $(PYTHON) -m aegisgraph.cli

.PHONY: tooling test validate extract reprochain-build reprochain-run reprochain-map polydiff-regression smabench reproduce export-private export-public-sanitized

tooling:
	$(AEGISGRAPH) tooling

test:
	$(PYTHON) -m pytest

validate:
	$(AEGISGRAPH) validate

extract:
	$(AEGISGRAPH) extract

reprochain-build:
	$(AEGISGRAPH) reprochain build

reprochain-run:
	$(AEGISGRAPH) reprochain run

reprochain-map:
	$(AEGISGRAPH) reprochain map

polydiff-regression:
	$(AEGISGRAPH) polydiff regression

smabench:
	$(AEGISGRAPH) smabench run

reproduce: tooling extract reprochain-build reprochain-run reprochain-map polydiff-regression smabench validate export-private
	@echo "AegisGraph Tier 3 private reproduction scaffold complete."

export-private:
	$(AEGISGRAPH) export private

export-public-sanitized:
	$(AEGISGRAPH) export public-sanitized
