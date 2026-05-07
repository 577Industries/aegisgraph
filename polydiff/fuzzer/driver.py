"""LibFuzzer-style mutation driver with axis-coverage heuristic.

Local-only. NOT in the deterministic `make reproduce` chain; runs from
`make polydiff-fuzz` (default budget 60s).

Design (per SPEC §5.8):

  - Seeds are drawn from `polydiff/fuzzer/seeds/` (populated from the
    regression corpus on demand) plus a hand-crafted set of
    "interesting" URL fragments.
  - The mutator applies cheap byte-level mutations (insert/delete/swap,
    bit-flips, shift one octet up/down). No structure-aware splicing
    yet — that's a v2 enhancement.
  - The runner runs every available wrapper on each mutation and feeds
    the resulting fact-vectors to `polydiff.disagreement.detector`.
  - Coverage heuristic: an input is "interesting" if it produces a
    Disagreement on an axis that no prior corpus input produced. Such
    inputs are written to `polydiff/fuzzer/corpus/`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import random
import sys
import time
from pathlib import Path
from typing import Iterable


def _seed_path() -> Path:
    return Path(__file__).resolve().parent / "seeds"


def _corpus_path(root: Path | None = None) -> Path:
    base = root or Path(__file__).resolve().parents[2]
    return base / "polydiff" / "fuzzer" / "corpus"


# Mutation operators. Bounded; each returns a possibly-mutated bytes.
def _flip_bit(buf: bytes, rng: random.Random) -> bytes:
    if not buf:
        return buf
    i = rng.randrange(len(buf))
    return buf[:i] + bytes([buf[i] ^ (1 << rng.randrange(8))]) + buf[i + 1:]


def _insert_byte(buf: bytes, rng: random.Random) -> bytes:
    if len(buf) >= 4096:
        return buf
    i = rng.randrange(len(buf) + 1)
    return buf[:i] + bytes([rng.randrange(256)]) + buf[i:]


def _delete_byte(buf: bytes, rng: random.Random) -> bytes:
    if len(buf) <= 1:
        return buf
    i = rng.randrange(len(buf))
    return buf[:i] + buf[i + 1:]


def _swap_bytes(buf: bytes, rng: random.Random) -> bytes:
    if len(buf) < 2:
        return buf
    i, j = rng.sample(range(len(buf)), 2)
    out = bytearray(buf)
    out[i], out[j] = out[j], out[i]
    return bytes(out)


def _splice_special(buf: bytes, rng: random.Random) -> bytes:
    """Insert one of the URL-spec-relevant special chars."""
    if len(buf) >= 4096:
        return buf
    specials = [b"\\", b"/", b"@", b":", b".", b"%", b"\t", b"\n", b"\r", b"#", b"?", b"["]
    i = rng.randrange(len(buf) + 1)
    return buf[:i] + rng.choice(specials) + buf[i:]


_OPERATORS = (_flip_bit, _insert_byte, _delete_byte, _swap_bytes, _splice_special)


def mutate(buf: bytes, rng: random.Random) -> bytes:
    """Apply 1-3 random operators to `buf`."""
    out = buf
    for _ in range(1 + rng.randrange(3)):
        out = rng.choice(_OPERATORS)(out, rng)
        if not out:
            out = b"http://x/"
    return out


def _initial_seeds(root: Path) -> list[bytes]:
    """Read seeds from disk and from the regression corpus."""
    out: list[bytes] = []
    seed_dir = _seed_path()
    if seed_dir.exists():
        for f in seed_dir.iterdir():
            if f.is_file():
                out.append(f.read_bytes())

    # Pull short URLs from the regression CASES.
    sys.path.insert(0, str(root))
    try:
        from polydiff.regression.build_corpus import CASES  # type: ignore[import-not-found]
        for c in CASES[:10]:
            out.append(c.input_url.encode("utf-8"))
    except Exception:
        pass
    finally:
        if str(root) in sys.path:
            sys.path.remove(str(root))
    if not out:
        out.append(b"https://example.com/")
    return out


def run(
    root: Path,
    budget_seconds: float = 60.0,
    out_dir: Path | None = None,
    seed: int | None = None,
) -> dict[str, object]:
    """Run the fuzzer for `budget_seconds` and return summary stats."""
    from aegisgraph.polydiff import fact_vectors_for, detect_disagreements

    rng = random.Random(seed)
    out_dir = out_dir or _corpus_path(root)
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds = _initial_seeds(root)
    queue: list[bytes] = list(seeds)
    seen_axes: set[str] = set()
    interesting_count = 0
    total = 0
    crashes: list[dict[str, str]] = []

    deadline = time.time() + budget_seconds
    while time.time() < deadline:
        # Replenish the queue from seeds when it's drained, so the
        # fuzzer keeps running for the full budget instead of falling
        # idle after the initial fan-out.
        if not queue:
            queue.extend(seeds)
        base = queue.pop(0)
        for _ in range(8):  # 8 mutations per base
            if time.time() >= deadline:
                break
            buf = mutate(base, rng)
            try:
                url = buf.decode("utf-8", errors="replace")
            except Exception:
                continue
            try:
                vectors = fact_vectors_for("FUZZ", url, root=root)
            except Exception as exc:
                crashes.append({"url": repr(url[:200]), "exception": str(exc)})
                continue
            total += 1
            try:
                disagreements = detect_disagreements(vectors)
            except Exception as exc:
                crashes.append({"url": repr(url[:200]), "exception": f"detector: {exc}"})
                continue
            new_axes = {d.axis for d in disagreements} - seen_axes
            if new_axes:
                interesting_count += 1
                seen_axes.update(new_axes)
                queue.append(buf)  # promote interesting input
                _persist(out_dir, buf)
            elif disagreements and rng.random() < 0.2:
                # Periodically promote a random disagreeing input to the
                # queue even if no new axes — keeps the search broader
                # than just unique-axis hits.
                queue.append(buf)

    return {
        "total_inputs": total,
        "interesting": interesting_count,
        "axes_covered": sorted(seen_axes),
        "crashes": crashes,
        "budget_seconds": budget_seconds,
    }


def _persist(out_dir: Path, buf: bytes) -> None:
    digest = hashlib.sha256(buf).hexdigest()[:16]
    (out_dir / f"input-{digest}").write_bytes(buf)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="polydiff-fuzz")
    parser.add_argument("--budget-seconds", type=float, default=60.0)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parents[2]
    summary = run(root, budget_seconds=args.budget_seconds, out_dir=args.out_dir, seed=args.seed)
    print(f"polydiff fuzzer summary:")
    print(f"  total_inputs : {summary['total_inputs']}")
    print(f"  interesting  : {summary['interesting']}")
    print(f"  axes_covered : {len(summary['axes_covered'])}")
    print(f"  crashes      : {len(summary['crashes'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
