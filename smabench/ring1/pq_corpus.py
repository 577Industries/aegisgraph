"""Post-quantum / Megolm corpus generator (Ring 1).

Emits synthetic PQXDH (Post-Quantum Extended Diffie-Hellman) traces and
Megolm withheld-key envelopes. NO real cryptography is performed —
every key, signature, and ciphertext field is a placeholder string
explicitly tagged `synthetic_NOT_REAL_*`. The corpus exists so a
state-machine handler can be exercised against the *shape* of the
envelope without depending on a working PQ stack at test time.

Cases enumerated:

- `pqxdh-initial` — first-message bundle; `prekey_signature` populated;
  `kyber_ciphertext` set; `oneTimeKyberPreKey` consumed flag false.
- `pqxdh-rotation` — bundle rotation event; `previous_signed_pre_key`
  carried alongside fresh `signed_pre_key`.
- `pqxdh-migration` — legacy X3DH envelope wrapped inside a PQXDH
  upgrade tag; carries a `migration_marker` for downgrade-resistance
  state-machine testing.
- `megolm-withheld` — Matrix m.room_key.withheld with `code` set to
  one of the canonical withheld-reason values, plus the room/session
  identifiers a state-machine consumer would route on.
- `megolm-replayed` — same `session_id` appearing in two consecutive
  forwarded_room_key messages; tests dedupe.
- `megolm-rotation` — sender rotates session mid-stream; test the
  consumer accepts the new session_id.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Iterator

from ._common import CorpusItem, write_corpus

NAME = "pq-corpus"
DEFAULT_COUNT = 60
DEFAULT_SEED = 42


def _hex_token(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def _synthetic_uuid(rng: random.Random) -> str:
    return (
        f"synthetic-{_hex_token(rng, 8)}-{_hex_token(rng, 4)}-"
        f"{_hex_token(rng, 4)}-{_hex_token(rng, 4)}-{_hex_token(rng, 12)}"
    )


def _pqxdh_initial(rng: random.Random) -> dict:
    return {
        "_synthetic_kind": "pqxdh-initial",
        "registration_id": rng.randrange(1, 16383),
        "device_id": rng.randrange(2, 2_000_000),
        "identity_key": "synthetic_NOT_REAL_ed25519",
        "signed_pre_key": {
            "key_id": rng.randrange(1, 1_000_000),
            "public_key": "synthetic_NOT_REAL_curve25519",
            "signature": "synthetic_NOT_REAL_signature",
        },
        "one_time_pre_key": {
            "key_id": rng.randrange(1, 1_000_000),
            "public_key": "synthetic_NOT_REAL_curve25519_otpk",
        },
        "kyber_pre_key": {
            "key_id": rng.randrange(1, 1_000_000),
            "public_key": "synthetic_NOT_REAL_kyber_pk",
            "signature": "synthetic_NOT_REAL_kyber_sig",
        },
        "kyber_ciphertext": "synthetic_NOT_REAL_kyber_ct",
        "one_time_kyber_pre_key_consumed": False,
        "session_uuid": _synthetic_uuid(rng),
    }


def _pqxdh_rotation(rng: random.Random) -> dict:
    return {
        "_synthetic_kind": "pqxdh-rotation",
        "device_id": rng.randrange(2, 2_000_000),
        "previous_signed_pre_key": {
            "key_id": rng.randrange(1, 1_000_000),
            "public_key": "synthetic_NOT_REAL_curve25519_prev",
        },
        "signed_pre_key": {
            "key_id": rng.randrange(1, 1_000_000),
            "public_key": "synthetic_NOT_REAL_curve25519_new",
            "signature": "synthetic_NOT_REAL_signature_new",
        },
        "kyber_pre_key": {
            "key_id": rng.randrange(1, 1_000_000),
            "public_key": "synthetic_NOT_REAL_kyber_pk_new",
            "signature": "synthetic_NOT_REAL_kyber_sig_new",
        },
        "rotated_at_ms": 1500000000_000,
        "session_uuid": _synthetic_uuid(rng),
    }


def _pqxdh_migration(rng: random.Random) -> dict:
    return {
        "_synthetic_kind": "pqxdh-migration",
        "migration_marker": "x3dh_to_pqxdh_v1",
        "downgrade_resistant": True,
        "legacy_envelope": {
            "type": "X3DH",
            "ratchet_key": "synthetic_NOT_REAL_curve25519",
            "counter": rng.randrange(0, 100),
        },
        "upgraded_envelope": {
            "type": "PQXDH",
            "kyber_ciphertext": "synthetic_NOT_REAL_kyber_ct",
            "ratchet_key": "synthetic_NOT_REAL_curve25519",
        },
        "session_uuid": _synthetic_uuid(rng),
    }


def _megolm_withheld(rng: random.Random) -> dict:
    code = rng.choice(["m.unverified", "m.blacklisted", "m.unauthorised", "m.no_olm", "m.unavailable"])
    return {
        "_synthetic_kind": "megolm-withheld",
        "type": "m.room_key.withheld",
        "content": {
            "algorithm": "m.megolm.v1.aes-sha2",
            "code": code,
            "reason": "synthetic withheld",
            "room_id": f"!synthetic_{_hex_token(rng, 8)}:example.org",
            "sender_key": "synthetic_NOT_REAL_curve25519",
            "session_id": f"synthetic_session_{_hex_token(rng, 12)}",
        },
    }


def _megolm_replayed(rng: random.Random) -> dict:
    session_id = f"synthetic_session_{_hex_token(rng, 12)}"
    return {
        "_synthetic_kind": "megolm-replayed",
        "session_id": session_id,
        "events": [
            {
                "type": "m.forwarded_room_key",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "session_id": session_id,
                    "session_key": "synthetic_NOT_REAL_session_key",
                    "room_id": f"!synthetic_{_hex_token(rng, 8)}:example.org",
                    "sender_claimed_ed25519_key": "synthetic_ed25519",
                    "forwarding_curve25519_key_chain": [],
                },
                "timestamp_ms": 1500000000_000,
            },
            {
                "type": "m.forwarded_room_key",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "session_id": session_id,  # same → replay
                    "session_key": "synthetic_NOT_REAL_session_key",
                    "room_id": f"!synthetic_{_hex_token(rng, 8)}:example.org",
                    "sender_claimed_ed25519_key": "synthetic_ed25519",
                    "forwarding_curve25519_key_chain": [],
                },
                "timestamp_ms": 1500000005_000,
            },
        ],
    }


def _megolm_rotation(rng: random.Random) -> dict:
    return {
        "_synthetic_kind": "megolm-rotation",
        "old_session_id": f"synthetic_session_{_hex_token(rng, 12)}",
        "new_session_id": f"synthetic_session_{_hex_token(rng, 12)}",
        "room_id": f"!synthetic_{_hex_token(rng, 8)}:example.org",
        "rotation_period_ms": 7 * 24 * 3600 * 1000,
        "rotation_period_msgs": 100,
        "trigger": rng.choice(["scheduled", "membership_change", "device_key_change"]),
    }


_BUILDERS = {
    "pqxdh-initial": _pqxdh_initial,
    "pqxdh-rotation": _pqxdh_rotation,
    "pqxdh-migration": _pqxdh_migration,
    "megolm-withheld": _megolm_withheld,
    "megolm-replayed": _megolm_replayed,
    "megolm-rotation": _megolm_rotation,
}


def _items(rng: random.Random, count: int) -> Iterator[CorpusItem]:
    cases = list(_BUILDERS.keys())
    rounds = (count // len(cases)) + 1
    yielded = 0
    for round_idx in range(rounds):
        for case in cases:
            if yielded >= count:
                return
            payload_obj = _BUILDERS[case](rng)
            payload_obj["_synthetic_round"] = round_idx
            payload_bytes = (
                json.dumps(payload_obj, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
            ).encode("utf-8")
            yield CorpusItem(
                payload=payload_bytes,
                extension="json",
                category=case,
                extra={"case": case, "round": round_idx},
            )
            yielded += 1


def generate(corpus_dir: Path, *, count: int = DEFAULT_COUNT, seed: int = DEFAULT_SEED) -> dict:
    rng = random.Random(seed)
    items = list(_items(rng, count))
    return write_corpus(
        corpus_dir,
        items,
        name=NAME,
        source_policy="synthetic",
        publication_policy="sanitized_candidate",
        seed=seed,
        count=count,
        generator_extra={
            "module": "smabench.ring1.pq_corpus",
            "cases": list(_BUILDERS.keys()),
            "policy": "synthetic_only_no_real_cryptography",
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the SMABench Ring 1 PQ corpus.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    out = args.out or (Path(__file__).resolve().parents[2] / "smabench" / "ring1" / "pq-corpus")
    md = generate(out, count=args.count, seed=args.seed)
    print(f"pq-corpus: {md['item_count']} items, sha256={md['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
