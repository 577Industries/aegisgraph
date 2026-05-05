from __future__ import annotations

CLAIM_STATES = (
    "observed",
    "anchored",
    "scored",
    "validation_tasked",
    "reviewed",
    "accepted",
    "limited",
    "retired",
)

CLAIM_STATE_ORDER = {state: index for index, state in enumerate(CLAIM_STATES)}

PATH_CLASSES = (
    "inbound_message",
    "media_decode",
    "link_preview",
    "deeplink",
    "qr_device_link",
    "sync_state",
    "crypto_key_lifecycle",
    "native_boundary",
)

SCORE_DIMENSIONS = (
    "remote_reachability",
    "attacker_control",
    "parser_complexity",
    "native_boundary",
    "auth_boundary",
    "privilege_impact",
    "exploit_history",
    "mitigation_strength",
    "observability",
    "confidence",
)

TARGETS = {
    "signal": {
        "name": "Signal Android",
        "repo_url": "https://github.com/signalapp/Signal-Android",
        "commit": "1043851",
        "source_policy": "anchor-only",
        "graph_dir": "signal",
        "public_artifact_id": "signal_android_1043851",
    },
    "element-x": {
        "name": "Element X Android",
        "repo_url": "https://github.com/element-hq/element-x-android",
        "commit": "91d265e6",
        "source_policy": "anchor-only",
        "graph_dir": "element-x",
        "public_artifact_id": "elementx_android_91d265e6",
    },
}

STATIC_GENERATED_AT = "2026-05-05T00:00:00Z"
