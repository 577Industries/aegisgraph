# CrossSMA Target Registry

This directory holds the YAML manifest of SMA targets that CrossSMA
queries fan out to. The manifest is loaded by
`aegisgraph/crosssma/target_registry.py`.

## Files

* `targets.yaml` - 4-target manifest at M5.5
  (signal-android, element-x-android, wire-android, telegram-android).

## Verified vs stub targets

A target's `verified: true` field asserts that the `commit` value has
been visually confirmed against the upstream repository. `verified:
false` marks a stub entry whose commit pin is a placeholder string
prefixed with `TODO-` and MUST be accompanied by a `deferred_to`
field (see below) so it cannot drift silently.

| target_id | verified | commit shape | source of pin |
|---|---|---|---|
| signal-android | yes | SHA | aegisgraph/constants.py:TARGETS\["signal"\] |
| element-x-android | yes | SHA | aegisgraph/constants.py:TARGETS\["element-x"\] |
| wire-android | no | `TODO-WIRE-COMMIT` | placeholder; deferred to M22.1 |
| telegram-android | no | `TODO-TELEGRAM-COMMIT` | placeholder; deferred to M22.1 |

## Additive `deferred_to` field (Wave 9C)

Per ADR-0010 additive-only schema policy, the registry schema gained
two optional fields in Wave 9C:

* `deferred_to` -- milestone id of the form `M<digits>[.<digits>...]`
  (e.g. `M22.1`) that will resolve a placeholder commit pin.
  **Required** whenever `commit` matches the pattern `TODO-*-COMMIT`.
* `deferral_note` -- prose rationale for the deferral.

The wire-android and telegram-android entries are deferred to
**M22.1** ("additional SMA target authorization", Phase II plan §25
external-block T-M22.1, PI + counsel-gated). Pinning HEAD without
authorized-target coordination just chases drift; the registry
prefers an honest deferral.

Guard tests:

* `tests/crosssma/test_targets_yaml_no_orphan_todo.py` -- a
  `TODO-*-COMMIT` placeholder without a companion `deferred_to`
  fails the suite.
* `tests/crosssma/test_targets_yaml_deferred_pattern.py` -- every
  `verified: false` entry must carry either a real SHA pin or
  `deferred_to`, and `deferred_to` values must look like a
  milestone id.

## Additive-extension contract

The two existing verified targets MUST agree with
`aegisgraph/constants.py:TARGETS`. If a Signal or Element X commit is
bumped, update both files in one PR. The test
`tests/crosssma/test_target_registry_loads_4_targets.py::test_signal_commit_pin_matches_global_constants`
enforces this.

This file does NOT mutate `aegisgraph.constants.TARGETS` at import or
load time. CrossSMA-local extensions stay CrossSMA-local until they
graduate to the global constants via an explicit constants.py edit.
