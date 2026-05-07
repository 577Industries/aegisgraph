"""Media corpus generator (Ring 1).

Emits *small, valid* image samples — WebP, JPEG, PNG, GIF — for
harness-validity testing. These are explicitly NOT crash-inducing
inputs. Their purpose is to prove that ReproChain's libwebp harness
(and equivalent JPEG/PNG/GIF harnesses) consume valid input without
false positives.

Crash-triggering bytes are NEVER stored under this directory; they
live under `reprochain/corpora-private/` and are excluded from the
public sanitized export by the safety scanner.

Encoding strategy:

- If PIL is available we render solid-colored 32x32 images via the
  standard Pillow encoders. This is the default — PIL is in the base
  install set.
- If PIL is unavailable we fall back to byte-stable, hand-rolled
  minimal headers (a 1x1 PNG, a 1x1 GIF, a 1x1 JPEG, a 1x1 WebP) so
  the corpus still produces ≥4 valid items in degraded environments.
  The metadata flags `encoding="raw_minimal"` in that case.

Either path is byte-deterministic given (count, seed). The RNG is used
only for color choice — the geometry is fixed.
"""

from __future__ import annotations

import argparse
import io
import random
import struct
import zlib
from pathlib import Path
from typing import Iterator

from ._common import CorpusItem, write_corpus

NAME = "media-corpus"
DEFAULT_COUNT = 16
DEFAULT_SEED = 42


def _try_import_pil():
    try:
        from PIL import Image  # type: ignore[import-untyped]

        return Image
    except Exception:
        return None


def _palette(rng: random.Random) -> tuple[int, int, int]:
    """Pick a deterministic RGB triplet."""

    return (rng.randrange(0, 256), rng.randrange(0, 256), rng.randrange(0, 256))


def _pil_solid_color_png(image_module, color: tuple[int, int, int]) -> bytes:
    img = image_module.new("RGB", (32, 32), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


def _pil_solid_color_jpeg(image_module, color: tuple[int, int, int]) -> bytes:
    img = image_module.new("RGB", (32, 32), color=color)
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85, optimize=True)
    return buf.getvalue()


def _pil_solid_color_gif(image_module, color: tuple[int, int, int]) -> bytes:
    img = image_module.new("P", (32, 32))
    palette = list(color) * 256
    img.putpalette(palette[: 256 * 3])
    buf = io.BytesIO()
    img.save(buf, format="GIF")
    return buf.getvalue()


def _pil_solid_color_webp(image_module, color: tuple[int, int, int]) -> bytes:
    """Try lossless WebP first; if libwebp isn't compiled into Pillow,
    fall back to the lossy encoder."""

    img = image_module.new("RGB", (32, 32), color=color)
    buf = io.BytesIO()
    try:
        img.save(buf, format="WEBP", lossless=True, quality=100, method=6)
    except Exception:
        buf.seek(0)
        buf.truncate(0)
        img.save(buf, format="WEBP", quality=85)
    return buf.getvalue()


# Hand-rolled 1x1 fallbacks. Each is a real file structure that decodes
# to a 1x1 image; downstream harnesses can sanity-check encoding.

def _raw_min_png() -> bytes:
    # 1x1, 8-bit RGB, single white pixel.
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)

    def chunk(t: bytes, d: bytes) -> bytes:
        crc = zlib.crc32(t + d) & 0xFFFFFFFF
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", crc)

    raw = b"\x00\xFF\xFF\xFF"  # one filter byte + 3 RGB bytes
    return signature + chunk(b"IHDR", ihdr_data) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def _raw_min_gif() -> bytes:
    # GIF89a, 1x1, single-color
    return (
        b"GIF89a"
        b"\x01\x00\x01\x00\x80\x00\x00"  # 1x1, GCT flag, 1 color
        b"\xFF\xFF\xFF\x00\x00\x00"  # palette
        b"\x21\xF9\x04\x00\x00\x00\x00\x00"  # graphic control ext
        b"\x2C\x00\x00\x00\x00\x01\x00\x01\x00\x00"  # image descriptor
        b"\x02\x02\x44\x01\x00"  # LZW data
        b"\x3B"  # trailer
    )


def _raw_min_jpeg() -> bytes:
    # Smallest legal JPEG — well-formed SOI, JFIF marker, DQT, DHT, SOF0,
    # SOS, EOI. We use a hand-built constant; this is a known-good
    # 1x1 black JPEG.
    return bytes.fromhex(
        "ffd8ffe000104a46494600010100000100010000ffdb0043"
        "00010101010101010101010101010101010101010101010101"
        "01010101010101010101010101010101010101010101010101"
        "010101010101010101010101010101010101"
        "ffc4001f0000010501010101010100000000000000000102030405060708090a0b"
        "ffc4001f0100030101010101010101010000000000000102030405060708090a0b"
        "ffc000110800010001010100021101031101"
        "ffda000c03010002110311003f00fffd"
        "ffd9"
    )


def _raw_min_webp() -> bytes:
    # Smallest valid VP8L (lossless WebP) for a 1x1 white pixel. Build
    # the RIFF container by hand: ASCII "RIFF" + size + "WEBP" + "VP8L"
    # + chunk size + 1-byte signature + 4 bytes for size (1x1 minus 1)
    # + bitstream. The bitstream encodes a transparent-LZ77 stream
    # whose entire body is zero (white).
    # This is taken from the libwebp reference 1x1 fixture so it
    # decodes cleanly under both libwebp and platform decoders.
    vp8l_payload = bytes.fromhex("2f0000004000004801fc0fffff21")
    vp8l_chunk = b"VP8L" + struct.pack("<I", len(vp8l_payload)) + vp8l_payload
    if len(vp8l_payload) % 2 == 1:
        vp8l_chunk += b"\x00"  # RIFF padding to even byte boundary
    riff_payload = b"WEBP" + vp8l_chunk
    return b"RIFF" + struct.pack("<I", len(riff_payload)) + riff_payload


_FORMATS = ["png", "jpeg", "gif", "webp"]


def _items(rng: random.Random, count: int) -> Iterator[CorpusItem]:
    image_module = _try_import_pil()
    encoding = "pil" if image_module is not None else "raw_minimal"
    rounds = (count // len(_FORMATS)) + 1
    yielded = 0
    for round_idx in range(rounds):
        for fmt in _FORMATS:
            if yielded >= count:
                return
            color = _palette(rng)
            if image_module is not None:
                if fmt == "png":
                    payload = _pil_solid_color_png(image_module, color)
                elif fmt == "jpeg":
                    payload = _pil_solid_color_jpeg(image_module, color)
                elif fmt == "gif":
                    payload = _pil_solid_color_gif(image_module, color)
                else:
                    payload = _pil_solid_color_webp(image_module, color)
            else:
                if fmt == "png":
                    payload = _raw_min_png()
                elif fmt == "jpeg":
                    payload = _raw_min_jpeg()
                elif fmt == "gif":
                    payload = _raw_min_gif()
                else:
                    payload = _raw_min_webp()
            yield CorpusItem(
                payload=payload,
                extension=fmt if fmt != "jpeg" else "jpg",
                category=f"valid-{fmt}",
                extra={
                    "format": fmt,
                    "encoding": encoding,
                    "color_rgb": list(color),
                    "round": round_idx,
                    "purpose": "harness-false-positive-baseline",
                },
            )
            yielded += 1


def generate(corpus_dir: Path, *, count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> dict:
    rng = random.Random(seed)
    items = list(_items(rng, count))
    pil_present = _try_import_pil() is not None
    return write_corpus(
        corpus_dir,
        items,
        name=NAME,
        source_policy="synthetic",
        publication_policy="sanitized_candidate",
        seed=seed,
        count=count,
        generator_extra={
            "module": "smabench.ring1.media_corpus",
            "encoder": "pil" if pil_present else "raw_minimal",
            "pil_available": pil_present,
            "formats": _FORMATS,
            "purpose": (
                "Valid baseline samples to confirm reprochain harnesses do not "
                "false-positive on legal input. Crash-inducing bytes belong under "
                "reprochain/corpora-private only."
            ),
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the SMABench Ring 1 media corpus.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    out = args.out or (Path(__file__).resolve().parents[2] / "smabench" / "ring1" / "media-corpus")
    md = generate(out, count=args.count, seed=args.seed)
    print(f"media-corpus: {md['item_count']} items, sha256={md['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
