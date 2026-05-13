"""PolyDiff URL family — the original (and currently only) family.

Subsequent families (image, opengraph, qr, deeplink, proto) will live
as siblings under `aegisgraph/polydiff/families/` per the Engine 1
design (see `Asemarefactor.md` and `plans/so-i-have-a-structured-milner.md`
§6). Each family follows the same shape:

- `profiles.py` — wrapper-dispatch + `fact_vectors_for`
- `regression.py` — corpus loader + `run_regression` entry
- (future) `family.yaml` — declared implementations + reachability map
"""

from __future__ import annotations

from .profiles import (
    PARSER_STATUS_FILENAME,
    fact_vectors_for,
    load_parser_status,
)
from .regression import run_regression


__all__ = [
    "PARSER_STATUS_FILENAME",
    "fact_vectors_for",
    "load_parser_status",
    "run_regression",
]
