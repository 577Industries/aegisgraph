"""URL corpus generator (Ring 1).

Emits ≥10k synthetic URLs covering a grid of cells known to disagree
across parser implementations: scheme, userinfo, host, port, path,
query, fragment, control chars. Output is per-input `<sha8>.txt` files
plus `corpus.metadata.json` with category labels.

The grid is enumerated deterministically and (when `count` exceeds the
exhaustive grid size) padded with seeded randomized variants so a third
party can reproduce the exact byte stream from `(count, seed)`.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path
from typing import Iterator

from ._common import CorpusItem, write_corpus

NAME = "url-corpus"
DEFAULT_COUNT = 10_000
DEFAULT_SEED = 42

# Grid axis values — chosen to cover historically interesting parser
# disagreement classes. Each is a (label, value) pair so the metadata
# carries the human-readable category.

_SCHEMES = [
    ("http", "http"),
    ("https", "https"),
    ("javascript", "javascript"),
    ("data", "data"),
    ("file", "file"),
    ("custom-app", "x-app"),
]

_USERINFO = [
    ("none", ""),
    ("empty", "@"),
    ("simple", "user@"),
    ("password", "user:pass@"),
    ("percent-encoded", "us%65r:p%61ss@"),
    ("backslash-confusion", "trusted.example\\@"),
    ("at-injected", "user@evil.example@"),
]

_HOSTS = [
    ("fqdn", "preview.example"),
    ("fqdn-trailing-dot", "preview.example."),
    ("idn-german", "xn--bcher-kva.example"),
    ("idn-cyrillic", "xn--80ak6aa92e.example"),
    ("ipv4-dotted", "192.0.2.1"),
    ("ipv4-octal", "0300.0000.0002.0001"),
    ("ipv4-decimal", "3221225985"),
    ("ipv4-hex", "0xC0000201"),
    ("ipv4-mixed", "0xC0.0.2.1"),
    ("ipv6-bracketed", "[2001:db8::1]"),
    ("ipv6-mapped-loopback", "[::ffff:127.0.0.1]"),
    ("ipv6-zoneid", "[fe80::1%25eth0]"),
    ("loopback-literal", "127.0.0.1"),
    ("loopback-name", "localhost"),
    ("private-rfc1918", "10.0.0.1"),
    ("link-local", "169.254.169.254"),
    ("malformed-double-dot", "preview..example"),
    ("malformed-empty-label", ".preview.example"),
    ("malformed-tld-only", "example"),
]

_PORTS = [
    ("default", ""),
    ("explicit-80", ":80"),
    ("explicit-443", ":443"),
    ("explicit-high", ":65535"),
    ("oversized", ":99999"),
    ("zero", ":0"),
]

_PATHS = [
    ("none", ""),
    ("root", "/"),
    ("normal", "/article/page"),
    ("traversal", "/../admin"),
    ("traversal-encoded", "/%2e%2e/admin"),
    ("traversal-double-encoded", "/%252e%252e/admin"),
    ("double-slash", "//etc//passwd"),
    ("trailing-slash", "/article/"),
    ("path-with-semicolon", "/article;jsessionid=abc"),
    ("path-with-control", "/article\x00stop"),
]

_QUERIES = [
    ("none", ""),
    ("simple", "?q=one"),
    ("encoded", "?q=hello%20world"),
    ("double-encoded", "?q=hello%2520world"),
    ("multi-pair", "?a=1&b=2"),
    ("ampersand-injected", "?a=1&amp;b=2"),
    ("equals-injection", "?a=b=c"),
]

_FRAGMENTS = [
    ("none", ""),
    ("simple", "#top"),
    ("encoded", "#sec%2Fone"),
    ("matrix-room", "#/room:example.org"),
]

# Categories that exist purely to test control-char handling. We avoid
# anything that could be interpreted as 0day in a parser; these are the
# canonical RFC-3986 reserved/control class boundaries.
_CONTROL_CHARS = ["\t", "\r", "\n", "\x00", "\x7f", " "]


def _join_url(
    scheme: str,
    userinfo: str,
    host: str,
    port: str,
    path: str,
    query: str,
    fragment: str,
) -> str:
    return f"{scheme}://{userinfo}{host}{port}{path}{query}{fragment}"


def _grid_iter() -> Iterator[CorpusItem]:
    """Emit one item per grid cell.

    The full Cartesian product is ~6 * 7 * 19 * 6 * 10 * 7 * 4 ≈ 1.3M
    which we don't want; instead we walk the axes in zip-with-padding
    style so every value is exercised at least once and we top out
    around the size of the largest axis times a small multiplier.
    """

    axis_values = [
        _SCHEMES,
        _USERINFO,
        _HOSTS,
        _PORTS,
        _PATHS,
        _QUERIES,
        _FRAGMENTS,
    ]
    longest = max(len(axis) for axis in axis_values)
    for layer in range(longest):
        for axis_index, axis in enumerate(axis_values):
            scheme_label, scheme = _SCHEMES[layer % len(_SCHEMES)]
            userinfo_label, userinfo = _USERINFO[layer % len(_USERINFO)]
            host_label, host = _HOSTS[layer % len(_HOSTS)]
            port_label, port = _PORTS[layer % len(_PORTS)]
            path_label, path = _PATHS[layer % len(_PATHS)]
            query_label, query = _QUERIES[layer % len(_QUERIES)]
            fragment_label, fragment = _FRAGMENTS[layer % len(_FRAGMENTS)]
            # Override the focus axis to the layer-shifted slot; this
            # guarantees we see every value of every axis at least once.
            if axis_index == 0:
                scheme_label, scheme = axis[layer % len(axis)]
            elif axis_index == 1:
                userinfo_label, userinfo = axis[layer % len(axis)]
            elif axis_index == 2:
                host_label, host = axis[layer % len(axis)]
            elif axis_index == 3:
                port_label, port = axis[layer % len(axis)]
            elif axis_index == 4:
                path_label, path = axis[layer % len(axis)]
            elif axis_index == 5:
                query_label, query = axis[layer % len(axis)]
            elif axis_index == 6:
                fragment_label, fragment = axis[layer % len(axis)]
            url = _join_url(scheme, userinfo, host, port, path, query, fragment)
            category = (
                f"grid:{scheme_label}|{userinfo_label}|{host_label}|"
                f"{port_label}|{path_label}|{query_label}|{fragment_label}"
            )
            yield CorpusItem(
                payload=url.encode("utf-8"),
                extension="txt",
                category=category,
                extra={
                    "scheme": scheme_label,
                    "userinfo": userinfo_label,
                    "host": host_label,
                    "port": port_label,
                    "path": path_label,
                    "query": query_label,
                    "fragment": fragment_label,
                    "kind": "grid",
                },
            )


def _random_iter(rng: random.Random) -> Iterator[CorpusItem]:
    """Infinite stream of grid cells chosen with deterministic RNG.

    Adds occasional control-char injections at random positions to
    exercise byte-level parser tolerance. Never raises; callers slice
    via itertools.islice to get exactly the items they want.
    """

    while True:
        scheme_label, scheme = rng.choice(_SCHEMES)
        userinfo_label, userinfo = rng.choice(_USERINFO)
        host_label, host = rng.choice(_HOSTS)
        port_label, port = rng.choice(_PORTS)
        path_label, path = rng.choice(_PATHS)
        query_label, query = rng.choice(_QUERIES)
        fragment_label, fragment = rng.choice(_FRAGMENTS)
        url = _join_url(scheme, userinfo, host, port, path, query, fragment)
        # 10% chance: inject a control char between two segments to
        # produce a fuzz-style input. The position is RNG-driven so it
        # remains deterministic.
        if rng.random() < 0.1 and url:
            insert_at = rng.randrange(len(url))
            url = url[:insert_at] + rng.choice(_CONTROL_CHARS) + url[insert_at:]
            kind = "random-with-control"
        else:
            kind = "random"
        yield CorpusItem(
            payload=url.encode("utf-8"),
            extension="txt",
            category=(
                f"random:{scheme_label}|{userinfo_label}|{host_label}|"
                f"{port_label}|{path_label}|{query_label}|{fragment_label}"
            ),
            extra={
                "scheme": scheme_label,
                "userinfo": userinfo_label,
                "host": host_label,
                "port": port_label,
                "path": path_label,
                "query": query_label,
                "fragment": fragment_label,
                "kind": kind,
            },
        )


def generate(corpus_dir: Path, *, count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> dict:
    rng = random.Random(seed)
    items: list[CorpusItem] = []
    # Track payload bytes (not sha8) so de-dup is exact and not subject
    # to the prefix collision bound from `_common.CorpusItem.sha8`.
    seen_payloads: set[bytes] = set()

    # Phase 1: walk the grid (ensures every axis value is hit).
    # The axis-rotation walk produces duplicates (same axis combo
    # reachable through multiple `axis_index` lanes); de-dup explicitly.
    for item in _grid_iter():
        if len(items) >= count:
            break
        if item.payload in seen_payloads:
            continue
        seen_payloads.add(item.payload)
        items.append(item)

    # Phase 2: random fill with payload-level collision resolution.
    random_stream = _random_iter(rng)
    attempts = 0
    while len(items) < count and attempts < count * 16:
        attempts += 1
        candidate = next(random_stream)
        if candidate.payload in seen_payloads:
            continue
        seen_payloads.add(candidate.payload)
        items.append(candidate)
    if len(items) < count:
        # We exhausted the random space at the requested seed — surface
        # this clearly rather than silently emitting fewer items.
        raise RuntimeError(
            f"url-corpus: only generated {len(items)}/{count} unique items at seed {seed}; "
            "try a larger seed space or smaller count"
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
            "module": "smabench.ring1.url_corpus",
            "axes": [
                "scheme",
                "userinfo",
                "host",
                "port",
                "path",
                "query",
                "fragment",
            ],
            "axis_value_counts": {
                "scheme": len(_SCHEMES),
                "userinfo": len(_USERINFO),
                "host": len(_HOSTS),
                "port": len(_PORTS),
                "path": len(_PATHS),
                "query": len(_QUERIES),
                "fragment": len(_FRAGMENTS),
            },
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the SMABench Ring 1 URL corpus.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=None, help="Output directory (default: smabench/ring1/url-corpus)")
    args = parser.parse_args(argv)
    out = args.out or (Path(__file__).resolve().parents[2] / "smabench" / "ring1" / "url-corpus")
    metadata = generate(out, count=args.count, seed=args.seed)
    print(f"url-corpus: {metadata['item_count']} items, sha256={metadata['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
