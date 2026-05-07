"""Sync corpus generator (Ring 1).

Emits synthetic Matrix `/sync` responses (JSON) and Signal sync envelope
shells. Intentionally synthetic — every cryptographic field is a fixed
placeholder string, every UUID is `synthetic-`-prefixed, and we do NOT
ship anything that resembles a real session, key, or device certificate.

Cases enumerated:

- `matrix-empty-sync` — newly-created room, empty timeline, presence
  empty. Tests baseline state-machine handler.
- `matrix-replayed-event` — the same `event_id` appears twice with
  different `origin_server_ts` values. Tests dedupe handling.
- `matrix-key-rotation` — a `m.room_key_request` followed by a
  `m.forwarded_room_key`. Tests rotation pathway.
- `matrix-withheld-key` — a `m.room_key.withheld` event with reason
  set. Tests UX/state-machine for withheld decryption material.
- `signal-empty` — empty multi-device sync envelope.
- `signal-rekey` — a `SyncMessage.Sent` for a Sender-Key rotation.
- `signal-pre-key-shim` — a Sealed-Sender pre-key envelope shim
  (synthetic, not actually sealed).

We deliberately do NOT use a real protobuf encoder — Tier 3 doesn't
ship the protobuf definitions for Signal's wire format and we don't
want to pretend we have them. Instead Signal envelopes are encoded as
canonical JSON with a `_synthetic_signal_envelope: true` flag. A Ring 1
harness can pick this up and route to the Signal-shaped consumer.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Iterator

from ._common import CorpusItem, write_corpus

NAME = "sync-corpus"
DEFAULT_COUNT = 200
DEFAULT_SEED = 42


_MATRIX_CASES = [
    "empty-sync",
    "replayed-event",
    "key-rotation",
    "withheld-key",
    "presence-update",
    "ephemeral-typing",
    "redaction",
    "membership-change",
]

_SIGNAL_CASES = [
    "empty",
    "rekey",
    "pre-key-shim",
    "device-link-confirm",
    "verified-state-update",
    "sticker-pack-sync",
    "configuration-sync",
]


def _hex_token(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def _synthetic_event_id(rng: random.Random) -> str:
    return f"$synthetic_{_hex_token(rng, 16)}:example.org"


def _synthetic_room_id(rng: random.Random) -> str:
    return f"!synthetic_{_hex_token(rng, 12)}:example.org"


def _synthetic_user_id(rng: random.Random) -> str:
    return f"@synthetic_{_hex_token(rng, 10)}:example.org"


def _matrix_empty_sync(rng: random.Random) -> dict:
    next_batch = f"s_synthetic_{_hex_token(rng, 8)}"
    return {
        "next_batch": next_batch,
        "rooms": {"join": {}, "invite": {}, "leave": {}},
        "presence": {"events": []},
        "to_device": {"events": []},
        "device_lists": {"changed": [], "left": []},
        "_synthetic_kind": "matrix-empty-sync",
    }


def _matrix_replayed_event(rng: random.Random) -> dict:
    room = _synthetic_room_id(rng)
    user = _synthetic_user_id(rng)
    event_id = _synthetic_event_id(rng)
    base_event = {
        "event_id": event_id,
        "type": "m.room.message",
        "sender": user,
        "origin_server_ts": 1500000000,
        "content": {"body": "synthetic", "msgtype": "m.text"},
    }
    duplicate = dict(base_event)
    duplicate["origin_server_ts"] = 1500000005  # later — replay attempt
    return {
        "next_batch": f"s_synthetic_{_hex_token(rng, 8)}",
        "rooms": {
            "join": {
                room: {
                    "timeline": {"events": [base_event, duplicate], "limited": False, "prev_batch": "synthetic_prev"},
                    "state": {"events": []},
                    "ephemeral": {"events": []},
                    "account_data": {"events": []},
                }
            },
            "invite": {},
            "leave": {},
        },
        "_synthetic_kind": "matrix-replayed-event",
        "_synthetic_replay_pair": [base_event["event_id"], duplicate["event_id"]],
    }


def _matrix_key_rotation(rng: random.Random) -> dict:
    user = _synthetic_user_id(rng)
    return {
        "next_batch": f"s_synthetic_{_hex_token(rng, 8)}",
        "to_device": {
            "events": [
                {
                    "type": "m.room_key_request",
                    "sender": user,
                    "content": {
                        "action": "request",
                        "body": {"algorithm": "m.megolm.v1.aes-sha2", "session_id": f"synthetic_{_hex_token(rng, 12)}"},
                        "request_id": f"synthetic_{_hex_token(rng, 8)}",
                        "requesting_device_id": f"SYN{_hex_token(rng, 4)}",
                    },
                },
                {
                    "type": "m.forwarded_room_key",
                    "sender": user,
                    "content": {
                        "algorithm": "m.megolm.v1.aes-sha2",
                        "room_id": _synthetic_room_id(rng),
                        "session_id": f"synthetic_{_hex_token(rng, 12)}",
                        "session_key": "synthetic_key_material_NOT_REAL",
                        "sender_claimed_ed25519_key": "synthetic_ed25519",
                        "forwarding_curve25519_key_chain": [],
                    },
                },
            ]
        },
        "_synthetic_kind": "matrix-key-rotation",
    }


def _matrix_withheld_key(rng: random.Random) -> dict:
    user = _synthetic_user_id(rng)
    return {
        "next_batch": f"s_synthetic_{_hex_token(rng, 8)}",
        "to_device": {
            "events": [
                {
                    "type": "m.room_key.withheld",
                    "sender": user,
                    "content": {
                        "algorithm": "m.megolm.v1.aes-sha2",
                        "code": "m.unverified",
                        "reason": "synthetic withheld",
                        "room_id": _synthetic_room_id(rng),
                        "sender_key": "synthetic_curve25519",
                        "session_id": f"synthetic_{_hex_token(rng, 12)}",
                    },
                }
            ]
        },
        "_synthetic_kind": "matrix-withheld-key",
    }


def _matrix_presence_update(rng: random.Random) -> dict:
    return {
        "next_batch": f"s_synthetic_{_hex_token(rng, 8)}",
        "presence": {
            "events": [
                {
                    "type": "m.presence",
                    "sender": _synthetic_user_id(rng),
                    "content": {"presence": "online", "last_active_ago": 1000, "currently_active": True},
                }
            ]
        },
        "_synthetic_kind": "matrix-presence-update",
    }


def _matrix_ephemeral_typing(rng: random.Random) -> dict:
    return {
        "next_batch": f"s_synthetic_{_hex_token(rng, 8)}",
        "rooms": {
            "join": {
                _synthetic_room_id(rng): {
                    "ephemeral": {"events": [{"type": "m.typing", "content": {"user_ids": [_synthetic_user_id(rng)]}}]}
                }
            }
        },
        "_synthetic_kind": "matrix-ephemeral-typing",
    }


def _matrix_redaction(rng: random.Random) -> dict:
    target = _synthetic_event_id(rng)
    return {
        "next_batch": f"s_synthetic_{_hex_token(rng, 8)}",
        "rooms": {
            "join": {
                _synthetic_room_id(rng): {
                    "timeline": {
                        "events": [
                            {
                                "event_id": _synthetic_event_id(rng),
                                "type": "m.room.redaction",
                                "sender": _synthetic_user_id(rng),
                                "redacts": target,
                                "origin_server_ts": 1500000010,
                                "content": {"reason": "synthetic"},
                            }
                        ],
                        "limited": False,
                        "prev_batch": "synthetic_prev",
                    }
                }
            }
        },
        "_synthetic_kind": "matrix-redaction",
    }


def _matrix_membership_change(rng: random.Random) -> dict:
    return {
        "next_batch": f"s_synthetic_{_hex_token(rng, 8)}",
        "rooms": {
            "join": {
                _synthetic_room_id(rng): {
                    "timeline": {
                        "events": [
                            {
                                "event_id": _synthetic_event_id(rng),
                                "type": "m.room.member",
                                "sender": _synthetic_user_id(rng),
                                "state_key": _synthetic_user_id(rng),
                                "origin_server_ts": 1500000020,
                                "content": {"membership": "join"},
                            }
                        ],
                        "limited": False,
                        "prev_batch": "synthetic_prev",
                    }
                }
            }
        },
        "_synthetic_kind": "matrix-membership-change",
    }


_MATRIX_BUILDERS = {
    "empty-sync": _matrix_empty_sync,
    "replayed-event": _matrix_replayed_event,
    "key-rotation": _matrix_key_rotation,
    "withheld-key": _matrix_withheld_key,
    "presence-update": _matrix_presence_update,
    "ephemeral-typing": _matrix_ephemeral_typing,
    "redaction": _matrix_redaction,
    "membership-change": _matrix_membership_change,
}


def _signal_envelope(kind: str, rng: random.Random, body: dict) -> dict:
    """Wrap a Signal-shaped body in our synthetic envelope shape.

    We do NOT use a protobuf serializer — we don't ship the Signal
    `.proto` files in this repo and we don't want to fake them. The
    `_synthetic_signal_envelope` flag is the contract a downstream
    consumer must check before treating any field as wire-true.
    """

    return {
        "_synthetic_signal_envelope": True,
        "kind": kind,
        "device_id": int(rng.randrange(2, 2_000_000)),
        "source_uuid": f"synthetic-{_hex_token(rng, 8)}-{_hex_token(rng, 4)}-{_hex_token(rng, 4)}-{_hex_token(rng, 4)}-{_hex_token(rng, 12)}",
        "timestamp_ms": 1500000000_000,
        "body": body,
    }


def _signal_empty(rng: random.Random) -> dict:
    return _signal_envelope("empty", rng, {"sync_message": {"empty": True}})


def _signal_rekey(rng: random.Random) -> dict:
    return _signal_envelope(
        "rekey",
        rng,
        {
            "sync_message": {
                "sender_key_distribution": {
                    "group_id": f"synthetic_group_{_hex_token(rng, 8)}",
                    "distribution_id": f"synthetic_dist_{_hex_token(rng, 8)}",
                    "distribution_blob": "synthetic_NOT_REAL_KEY",
                }
            }
        },
    )


def _signal_pre_key_shim(rng: random.Random) -> dict:
    return _signal_envelope(
        "pre-key-shim",
        rng,
        {
            "envelope_type": "PREKEY_BUNDLE",
            "pre_key_id": int(rng.randrange(1, 1_000_000)),
            "signed_pre_key_id": int(rng.randrange(1, 1_000_000)),
            "registration_id": int(rng.randrange(1, 16383)),
            "identity_key": "synthetic_ed25519_NOT_REAL",
            "base_key": "synthetic_curve25519_NOT_REAL",
        },
    )


def _signal_device_link_confirm(rng: random.Random) -> dict:
    return _signal_envelope(
        "device-link-confirm",
        rng,
        {
            "sync_message": {
                "linked_device_added": {
                    "name": f"synthetic-device-{_hex_token(rng, 4)}",
                    "id": int(rng.randrange(2, 2_000_000)),
                }
            }
        },
    )


def _signal_verified_state_update(rng: random.Random) -> dict:
    return _signal_envelope(
        "verified-state-update",
        rng,
        {
            "sync_message": {
                "verified": {
                    "destination_uuid": f"synthetic-{_hex_token(rng, 16)}",
                    "state": "VERIFIED",
                    "identity_key": "synthetic_ed25519_NOT_REAL",
                }
            }
        },
    )


def _signal_sticker_pack_sync(rng: random.Random) -> dict:
    return _signal_envelope(
        "sticker-pack-sync",
        rng,
        {
            "sync_message": {
                "sticker_pack_operation": [
                    {"pack_id": _hex_token(rng, 16), "type": "INSTALL"}
                ]
            }
        },
    )


def _signal_configuration_sync(rng: random.Random) -> dict:
    return _signal_envelope(
        "configuration-sync",
        rng,
        {
            "sync_message": {
                "configuration": {
                    "read_receipts": True,
                    "typing_indicators": True,
                    "link_previews": False,
                    "unidentified_delivery_indicators": True,
                }
            }
        },
    )


_SIGNAL_BUILDERS = {
    "empty": _signal_empty,
    "rekey": _signal_rekey,
    "pre-key-shim": _signal_pre_key_shim,
    "device-link-confirm": _signal_device_link_confirm,
    "verified-state-update": _signal_verified_state_update,
    "sticker-pack-sync": _signal_sticker_pack_sync,
    "configuration-sync": _signal_configuration_sync,
}


def _items(rng: random.Random, count: int) -> Iterator[CorpusItem]:
    # Walk the case lists round-robin so we get even coverage across
    # both Matrix and Signal cases regardless of `count`. We re-seed
    # local RNG draws per case from the master rng so two consecutive
    # rounds with the same case still produce different payloads.
    cases: list[tuple[str, str]] = []
    for case in _MATRIX_CASES:
        cases.append(("matrix", case))
    for case in _SIGNAL_CASES:
        cases.append(("signal", case))
    rounds = (count // len(cases)) + 1
    yielded = 0
    for round_idx in range(rounds):
        for family, case in cases:
            if yielded >= count:
                return
            if family == "matrix":
                payload_obj = _MATRIX_BUILDERS[case](rng)
            else:
                payload_obj = _SIGNAL_BUILDERS[case](rng)
            payload_obj["_synthetic_round"] = round_idx
            payload_bytes = (
                json.dumps(payload_obj, sort_keys=True, indent=2, separators=(",", ": ")) + "\n"
            ).encode("utf-8")
            yield CorpusItem(
                payload=payload_bytes,
                extension="json",
                category=f"{family}-{case}",
                extra={"family": family, "case": case, "round": round_idx},
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
            "module": "smabench.ring1.sync_corpus",
            "matrix_cases": _MATRIX_CASES,
            "signal_cases": _SIGNAL_CASES,
        },
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the SMABench Ring 1 sync corpus.")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    out = args.out or (Path(__file__).resolve().parents[2] / "smabench" / "ring1" / "sync-corpus")
    md = generate(out, count=args.count, seed=args.seed)
    print(f"sync-corpus: {md['item_count']} items, sha256={md['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
