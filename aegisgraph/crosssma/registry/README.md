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
prefixed with `TODO-` and MUST be replaced before any analysis
fan-out is treated as authoritative.

| target_id | verified | source of pin |
|---|---|---|
| signal-android | yes | aegisgraph/constants.py:TARGETS\["signal"\] |
| element-x-android | yes | aegisgraph/constants.py:TARGETS\["element-x"\] |
| wire-android | no | placeholder (graduates at M11 per plan §5) |
| telegram-android | no | placeholder (graduates at M11 per plan §5) |

## Additive-extension contract

The two existing verified targets MUST agree with
`aegisgraph/constants.py:TARGETS`. If a Signal or Element X commit is
bumped, update both files in one PR. The test
`tests/crosssma/test_target_registry_loads_4_targets.py::test_signal_commit_pin_matches_global_constants`
enforces this.

This file does NOT mutate `aegisgraph.constants.TARGETS` at import or
load time. CrossSMA-local extensions stay CrossSMA-local until they
graduate to the global constants via an explicit constants.py edit.
