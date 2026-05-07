"""PolyDiff regression corpus.

The canonical case list lives in `polydiff/regression/build_corpus.py`
as Python data structures. The orchestrator (aegisgraph/polydiff.py)
reads from `CASES` directly so that the regression run does not depend
on on-disk directories existing.

The per-case directories under `polydiff/regression/cases/<id>/` are
optional documentation artifacts. They are populated by running
`python3 polydiff/regression/build_corpus.py` (or by `make
polydiff-build-corpus` once that target is wired). A subset of cases
ships with hand-written directories for ergonomic browsing; the full
set is generated on demand.
"""
