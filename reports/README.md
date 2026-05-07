# /reports/

Generated reports go here. Two paths owned by the validator-export stream:

- `reports/traceability_matrix.json` - machine-readable join of
  `docs/proposal-claims-index.yml` with `docs/dsip-requirements.yml` and
  every emitted `AG-EV-*` evidence record. One row per claim; columns for
  source location, evidence record id, validation status, and the
  responsible stream.

- `reports/traceability_matrix.md` - human-readable rendering of the same
  data, suitable for proposal-package inclusion.

Both files are produced by `make traceability` (which calls
`python -m validator.cli traceability`). Regenerate after every reproduce.

The integration stream provides:
- The empty skeleton input files (`docs/proposal-claims-index.yml`,
  `docs/dsip-requirements.yml`).
- The `traceability` Make target that the validator-export stream wires.
- This README documenting the output contract.

The validator-export stream provides:
- `validator/cli.py` (with the `traceability` subcommand).
- The actual `validator.traceability` module that performs the join.
- Concrete entries in the two skeleton input files.
