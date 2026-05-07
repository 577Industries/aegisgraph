"""QR corpus generator (Ring 1).

Emits PNG QR codes encoding device-linking payloads for both Signal
(`sgnl://linkdevice?...`) and Matrix MSC3906 (`https://matrix.to/#/?session_token=...`).
Cases include valid, expired, wrong-account, malformed, oversized, and
IDN-host-in-payload inputs.

Encoding strategy:

1. If the optional `qrcode` library is available we render real,
   scannable PNG QR codes — this is the default for the dev-container
   build that has the dep installed.
2. Otherwise we fall back to a *deterministic visual placeholder PNG*
   (built via PIL, which is in the default install set) and embed the
   payload inside a PNG `tEXt` chunk so a harness can recover the
   payload without scanning. Metadata flags this case as
   `encoding="placeholder_png"` so downstream harnesses can decide
   whether to skip or run a different validator. Metadata always
   carries the raw payload text so a Ring 1 consumer never has to
   actually decode the PNG to know what's inside.

Either way: byte-stable. The qrcode library is deterministic when
seeded (same payload + same parameters → same PNG); the PIL fallback
draws a payload-derived bit pattern.
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

NAME = "qr-corpus"
DEFAULT_COUNT = 32
DEFAULT_SEED = 42


# Cases drawn from the SPEC; each is a (category, payload-template-hint,
# expected_disposition) triple. Payload templates carry placeholders the
# generator fills with a deterministic synthetic UUID/token so the same
# (count, seed) yields byte-identical PNGs.
_QR_CASES = [
    ("signal-valid", "signal_valid", "valid", "sgnl://linkdevice?uuid={uuid}&pub_key={pubkey}"),
    ("signal-expired", "signal_expired", "expired", "sgnl://linkdevice?uuid={uuid}&pub_key={pubkey}&exp={old_ts}"),
    ("signal-wrong-account", "signal_wrong_account", "wrong_account", "sgnl://linkdevice?uuid={mismatch_uuid}&pub_key={pubkey}"),
    ("signal-malformed-truncated", "signal_truncated", "malformed", "sgnl://linkdevice?uuid={truncated}"),
    ("signal-malformed-checksum", "signal_bad_checksum", "malformed", "sgnl://linkdevice?uuid={uuid}&pub_key={pubkey}&csum=DEADBEEF"),
    ("signal-oversized", "signal_oversized", "oversized", "sgnl://linkdevice?uuid={uuid}&pub_key={pubkey}&padding={padding}"),
    ("signal-idn-host", "signal_idn", "malformed", "sgnl://linkdevice?uuid={uuid}&pub_key={pubkey}&relay=xn--bcher-kva.example"),
    ("matrix-valid", "matrix_valid", "valid", "https://matrix.to/#/?session_token={token}"),
    ("matrix-expired", "matrix_expired", "expired", "https://matrix.to/#/?session_token={token}&exp={old_ts}"),
    ("matrix-wrong-account", "matrix_wrong_account", "wrong_account", "https://matrix.to/#/?session_token={token}&user=@mismatch:example.org"),
    ("matrix-malformed-truncated", "matrix_truncated", "malformed", "https://matrix.to/#/?session_token={truncated}"),
    ("matrix-malformed-checksum", "matrix_bad_checksum", "malformed", "https://matrix.to/#/?session_token={token}&csum=DEADBEEF"),
    ("matrix-oversized", "matrix_oversized", "oversized", "https://matrix.to/#/?session_token={token}&padding={padding}"),
    ("matrix-idn-host", "matrix_idn", "malformed", "https://matrix.to/#/?session_token={token}&server=xn--bcher-kva.example"),
]


def _make_synthetic(rng: random.Random) -> dict[str, str]:
    """Mint a complete substitution dict for the case templates.

    Every value is RNG-derived (no datetime.now, no os.urandom). The
    synthetic UUIDs are clearly marked with the `synthetic-` prefix so
    a static check won't mistake them for real account IDs.
    """

    def hex_token(length: int) -> str:
        return "".join(rng.choice("0123456789abcdef") for _ in range(length))

    uuid = (
        f"synthetic-{hex_token(8)}-{hex_token(4)}-{hex_token(4)}-{hex_token(4)}-{hex_token(12)}"
    )
    return {
        "uuid": uuid,
        "mismatch_uuid": (
            f"synthetic-{hex_token(8)}-{hex_token(4)}-{hex_token(4)}-{hex_token(4)}-{hex_token(12)}"
        ),
        "pubkey": "synthetic_" + hex_token(64),
        "token": "synthetic_" + hex_token(48),
        "truncated": "synthetic_" + hex_token(8),
        # Use a stable past timestamp string (deterministic, no time.time()).
        "old_ts": "1500000000",
        # Padding is deterministic per RNG draw.
        "padding": hex_token(rng.randint(2_000, 4_000)),
    }


def _try_import_qrcode():
    """Return the qrcode module if available, else None.

    We isolate the import so the rest of the generator stays usable
    when the optional dep is absent.
    """

    try:
        import qrcode  # type: ignore[import-untyped]

        return qrcode
    except Exception:
        return None


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Build one PNG chunk (length, type, data, crc)."""

    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _placeholder_png(payload: str, *, size: int = 33) -> bytes:
    """Build a minimal grayscale PNG with a payload-derived bit pattern.

    Used when the `qrcode` library is unavailable. The bit pattern is
    deterministic in `payload`: each pixel is on/off based on a SHA-256
    bit unrolled across the image. We embed the original payload inside
    a `tEXt` chunk keyed `"smabench-qr-payload"` so a consumer can
    recover it directly. PIL is in the default install set; this
    function does not depend on it (we encode PNG by hand) so the
    placeholder works in environments stripped of optional deps.

    PNG layout: signature, IHDR, tEXt (payload), IDAT (filtered raw),
    IEND. We use 1-byte grayscale (color type 0, bit depth 8).
    """

    import hashlib

    seed = hashlib.sha256(payload.encode("utf-8")).digest()
    bits = []
    for byte in seed:
        for shift in range(8):
            bits.append((byte >> shift) & 1)
    # Tile the bits to fill `size*size`.
    needed = size * size
    while len(bits) < needed:
        # Re-hash to extend deterministically.
        seed = hashlib.sha256(seed).digest()
        for byte in seed:
            for shift in range(8):
                bits.append((byte >> shift) & 1)
    bits = bits[:needed]

    # Build raw image data with PNG filter byte 0 prepended per scanline.
    raw = bytearray()
    for row in range(size):
        raw.append(0)  # filter type: None
        for col in range(size):
            raw.append(0xFF if bits[row * size + col] == 0 else 0x00)
    compressed = zlib.compress(bytes(raw), level=9)

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0)
    ihdr = _png_chunk(b"IHDR", ihdr_data)
    text_data = b"smabench-qr-payload\x00" + payload.encode("utf-8")
    text_chunk = _png_chunk(b"tEXt", text_data)
    idat = _png_chunk(b"IDAT", compressed)
    iend = _png_chunk(b"IEND", b"")
    return signature + ihdr + text_chunk + idat + iend


def _qrcode_png(qrcode_mod, payload: str) -> bytes:
    """Render a real QR PNG via the qrcode library.

    Pin every option that affects output bytes so the result is byte-
    stable across runs: error correction level, box size, border, and
    the PIL backend that does the final encode.
    """

    import io as io_mod

    qr = qrcode_mod.QRCode(
        version=None,  # auto-fit
        error_correction=qrcode_mod.constants.ERROR_CORRECT_M,
        box_size=4,
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buf = io_mod.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def _items(rng: random.Random, count: int) -> Iterator[CorpusItem]:
    qrcode_mod = _try_import_qrcode()
    encoding_label = "qrcode_lib" if qrcode_mod is not None else "placeholder_png"

    # We yield in a deterministic order: walk cases round-robin, drawing
    # fresh synthetic substitutions per round so payloads vary but
    # remain reproducible.
    rounds = (count // len(_QR_CASES)) + 1
    yielded = 0
    for round_idx in range(rounds):
        if yielded >= count:
            break
        substitutions = _make_synthetic(rng)
        for case_label, case_id, disposition, template in _QR_CASES:
            if yielded >= count:
                break
            payload = template.format(**substitutions)
            if qrcode_mod is not None:
                png_bytes = _qrcode_png(qrcode_mod, payload)
            else:
                png_bytes = _placeholder_png(payload)
            yield CorpusItem(
                payload=png_bytes,
                extension="png",
                category=case_label,
                extra={
                    "case_id": case_id,
                    "disposition": disposition,
                    "encoding": encoding_label,
                    "raw_payload": payload,
                    "round": round_idx,
                },
            )
            yielded += 1


def generate(corpus_dir: Path, *, count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> dict:
    rng = random.Random(seed)
    items = list(_items(rng, count))
    qrcode_mod = _try_import_qrcode()
    return write_corpus(
        corpus_dir,
        items,
        name=NAME,
        source_policy="synthetic",
        publication_policy="sanitized_candidate",
        seed=seed,
        count=count,
        generator_extra={
            "module": "smabench.ring1.qr_corpus",
            "encoder": "qrcode_lib" if qrcode_mod is not None else "placeholder_png",
            "qrcode_lib_available": qrcode_mod is not None,
            "case_count": len(_QR_CASES),
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the SMABench Ring 1 QR corpus.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    out = args.out or (Path(__file__).resolve().parents[2] / "smabench" / "ring1" / "qr-corpus")
    md = generate(out, count=args.count, seed=args.seed)
    print(f"qr-corpus: {md['item_count']} items, sha256={md['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
