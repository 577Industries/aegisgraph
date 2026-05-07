"""Deep-link corpus generator (Ring 1).

Produces synthetic deep-link strings spanning the messenger schemes the
Tier 3 targets honor: `signal://`, `sgnl://`, `matrix://`, `element://`,
and `https://matrix.to/#/...`. Cells with attacker-controlled hosts,
paths, or fragments are interleaved so a downstream parser harness can
exercise the full disagreement surface without us having to ship a
separate "edge cases" file.

Output is per-string `<sha8>.txt` with `corpus.metadata.json` carrying
the category and parser-axis hint for each item.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path
from typing import Iterator

from ._common import CorpusItem, write_corpus

NAME = "deeplink-corpus"
DEFAULT_COUNT = 1_000
DEFAULT_SEED = 42


_SCHEMES = [
    ("signal", "signal://"),
    ("sgnl", "sgnl://"),
    ("matrix", "matrix://"),
    ("element", "element://"),
    ("matrix-to-https", "https://matrix.to/#/"),
]


_SIGNAL_PATHS = [
    ("conversation", "conversation/"),
    ("link-device", "linkdevice?uuid="),
    ("group", "group/"),
    ("call", "call/"),
    ("send", "send/"),
]

_MATRIX_PATHS = [
    ("user", "@"),
    ("room-id", "!"),
    ("room-alias", "#"),
    ("event-link", "event/"),
    ("link-device", "linkdevice/"),
]


_ATTACKER_HOSTS = [
    ("trusted-confusion", "trusted.example@evil.example"),
    ("idn-homograph", "xn--bcher-kva.example"),
    ("ipv4-octal", "0300.0000.0002.0001"),
    ("ipv6-mapped", "[::ffff:127.0.0.1]"),
    ("backslash-escape", "trusted.example\\@evil.example"),
    ("loopback", "127.0.0.1"),
    ("private-rfc1918", "10.0.0.1"),
    ("link-local", "169.254.169.254"),
    ("server-name", "matrix.org"),
    ("malformed-double-dot", "matrix..org"),
]

_PATH_INJECTIONS = [
    ("none", ""),
    ("traversal", "../admin"),
    ("traversal-encoded", "%2e%2e/admin"),
    ("crlf", "%0d%0aSet-Cookie:%20a=b"),
    ("nul", "%00admin"),
    ("script-fragment", "javascript:alert(1)"),
    ("matrix-room-suffix", ":matrix.org"),
    ("matrix-event-suffix", "/$evnt12345:matrix.org"),
]

_FRAGMENTS_TO_HTTPS = [
    ("none", ""),
    ("matrix-room", "?via=matrix.org"),
    ("session-token", "?session_token=PHANTOM"),
    ("invite", "?action=invite"),
    ("device-id", "?device_id=AABBCC"),
]


def _build_link(
    scheme: tuple[str, str],
    sub_path_label: str,
    sub_path: str,
    host_label: str,
    host: str,
    inj_label: str,
    inj: str,
    frag_label: str,
    frag: str,
) -> tuple[str, dict]:
    scheme_name, scheme_prefix = scheme
    if scheme_name == "matrix-to-https":
        # Matrix.to is sigil-driven (#/!@) inside the URL fragment.
        link = f"{scheme_prefix}{sub_path}{host}{inj}{frag}"
    elif scheme_name in ("matrix", "element"):
        # matrix:// uses sigils in the path component
        link = f"{scheme_prefix}{sub_path}{host}{inj}"
    else:
        link = f"{scheme_prefix}{sub_path}{host}{inj}"
    extra = {
        "scheme": scheme_name,
        "sub_path": sub_path_label,
        "host": host_label,
        "injection": inj_label,
        "fragment": frag_label,
    }
    return link, extra


def _grid_iter() -> Iterator[CorpusItem]:
    # Interleave schemes outermost-by-axis so a small count (e.g. 1000)
    # still touches every scheme family. Naive nesting would walk all
    # signal:// permutations first and only reach element:// after
    # ~6000 items.
    sub_paths_for_scheme = {}
    for scheme in _SCHEMES:
        scheme_name, _ = scheme
        sub_paths_for_scheme[scheme_name] = (
            _SIGNAL_PATHS if scheme_name in ("signal", "sgnl") else _MATRIX_PATHS
        )

    for frag_label, frag_value in _FRAGMENTS_TO_HTTPS:
        for inj_label, inj_value in _PATH_INJECTIONS:
            for host_label, host_value in _ATTACKER_HOSTS:
                # Round-robin scheme + sub_path so every scheme is hit
                # within the first cycle of a grid layer. The outer
                # loops above mean we still see the full Cartesian
                # product if `count` is large enough.
                for scheme in _SCHEMES:
                    scheme_name, _ = scheme
                    sub_paths = sub_paths_for_scheme[scheme_name]
                    for sub_label, sub_value in sub_paths:
                        link, extra = _build_link(
                            scheme,
                            sub_label,
                            sub_value,
                            host_label,
                            host_value,
                            inj_label,
                            inj_value,
                            frag_label,
                            frag_value,
                        )
                        yield CorpusItem(
                            payload=link.encode("utf-8"),
                            extension="txt",
                            category=(
                                f"{scheme_name}|{sub_label}|{host_label}|"
                                f"{inj_label}|{frag_label}"
                            ),
                            extra=extra,
                        )


def generate(corpus_dir: Path, *, count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> dict:
    rng = random.Random(seed)
    items: list[CorpusItem] = []
    seen: set[bytes] = set()

    # Phase 1: full grid, until we hit the requested count.
    for item in _grid_iter():
        if len(items) >= count:
            break
        if item.payload in seen:
            continue
        seen.add(item.payload)
        items.append(item)

    # Phase 2: random pad if grid didn't fill (only when count > grid size).
    grid_size = len(items)
    if grid_size < count:
        # Pad by swapping host/inj cells at random while keeping
        # scheme/sub-path coherent — emits new payloads with bounded RNG.
        attempts = 0
        max_attempts = (count - grid_size) * 16
        while len(items) < count and attempts < max_attempts:
            attempts += 1
            scheme = rng.choice(_SCHEMES)
            sub_paths = _SIGNAL_PATHS if scheme[0] in ("signal", "sgnl") else _MATRIX_PATHS
            sub_label, sub_value = rng.choice(sub_paths)
            host_label, host_value = rng.choice(_ATTACKER_HOSTS)
            inj_label, inj_value = rng.choice(_PATH_INJECTIONS)
            frag_label, frag_value = rng.choice(_FRAGMENTS_TO_HTTPS)
            link, extra = _build_link(
                scheme,
                sub_label,
                sub_value,
                host_label,
                host_value,
                inj_label,
                inj_value,
                frag_label,
                frag_value,
            )
            payload = link.encode("utf-8")
            if payload in seen:
                continue
            seen.add(payload)
            items.append(
                CorpusItem(
                    payload=payload,
                    extension="txt",
                    category=(
                        f"random:{scheme[0]}|{sub_label}|{host_label}|"
                        f"{inj_label}|{frag_label}"
                    ),
                    extra=extra,
                )
            )
        if len(items) < count:
            raise RuntimeError(
                f"deeplink-corpus: only generated {len(items)}/{count} unique items at seed {seed}"
            )

    return write_corpus(
        corpus_dir,
        items,
        name=NAME,
        source_policy="synthetic",
        publication_policy="sanitized_candidate",
        seed=seed,
        count=count,
        generator_extra={
            "module": "smabench.ring1.deeplink_corpus",
            "schemes": [s[0] for s in _SCHEMES],
            "axes": ["scheme", "sub_path", "host", "injection", "fragment"],
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the SMABench Ring 1 deeplink corpus.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    out = args.out or (Path(__file__).resolve().parents[2] / "smabench" / "ring1" / "deeplink-corpus")
    md = generate(out, count=args.count, seed=args.seed)
    print(f"deeplink-corpus: {md['item_count']} items, sha256={md['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
