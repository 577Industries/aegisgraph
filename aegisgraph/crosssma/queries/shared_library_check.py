"""shared_library_check: does target X depend on library L?

A target's `dependency_snapshot` is a tuple of `<library>@<version>`
tokens (or bare library names) captured during extraction. The query
returns a `SharedLibraryResult` carrying:

  * `present` - bool, whether at least one snapshot entry matches
  * `matched_dep` - the first matching token (or None)

Match semantics: a snapshot entry `libwebp@1.3.1` matches a query for
library `libwebp` iff the entry starts with `libwebp` and the next
character (if any) is `@` or `/` or `:` or end-of-string. This
prevents `libwebpd` from accidentally matching `libwebp`.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegisgraph.crosssma.target_registry import Target


@dataclass(frozen=True)
class SharedLibraryResult:
    target_id: str
    library: str
    present: bool
    matched_dep: str | None


_DELIMITERS = ("@", ":", "/")


def _dep_matches_library(dep: str, library: str) -> bool:
    if not dep.startswith(library):
        return False
    rest = dep[len(library):]
    if rest == "":
        return True
    return rest[0] in _DELIMITERS


def check_shared_library(target: Target, library: str) -> SharedLibraryResult:
    """Return whether `target` depends on `library`."""
    for dep in target.dependency_snapshot:
        if _dep_matches_library(dep, library):
            return SharedLibraryResult(
                target_id=target.target_id,
                library=library,
                present=True,
                matched_dep=dep,
            )
    return SharedLibraryResult(
        target_id=target.target_id,
        library=library,
        present=False,
        matched_dep=None,
    )


__all__ = ["SharedLibraryResult", "check_shared_library"]
