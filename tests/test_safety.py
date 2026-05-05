from aegisgraph.safety import blocking_flags, scan_record


def test_safety_scanner_blocks_live_probe_terms():
    flags = scan_record({"command": "nmap live target", "limitations": "bad"})
    assert any(flag.rule == "live_target_probing" for flag in blocking_flags(flags))


def test_safety_scanner_blocks_raw_crash_payload_fields():
    flags = scan_record({"raw_bytes": "AAEC", "limitations": "bad"})
    assert any(flag.rule == "undisclosed_crash_payload" for flag in blocking_flags(flags))


def test_safety_scanner_allows_bounded_anchor_only_record_language():
    flags = scan_record(
        {
            "claim_state": "validation_tasked",
            "limitations": "Anchor-only research record with no live interaction and no vulnerability claim.",
            "source_policy": "anchor-only",
        }
    )
    assert blocking_flags(flags) == []
