"""Template rendering must pass safety.scan_record with zero blocking flags.

This is the integration contract: anything we render to send to a vendor
or file as a CVE request goes through scan_record FIRST. If a template's
default rendering trips a BLOCKING_PATTERN, the disclosure pipeline is
broken — counsel review would never approve such an outbound letter.
"""

from __future__ import annotations

from aegisgraph.disclosure.pipeline import vendor_contact_router as vcr
from aegisgraph.disclosure.templates import render
from aegisgraph.safety import blocking_flags, scan_record


def _safe_context() -> dict:
    """A minimal sanitized context for first-contact letter rendering.

    Critically NO raw bytes, NO credentials, NO live-target probing
    language, NO overclaiming. The witness is referenced only by SHA.
    """
    return {
        "finding_id": "AG-DIS-IMG-0001",
        "vendor_name": "libwebp upstream (Google webmproject)",
        "vendor_contact": "security@chromium.org",
        "researcher_name": "577 Industries Coordinated Disclosure",
        "researcher_contact": "disclosure@577.industries",
        "triage_class": "image_decoder_divergence",
        "witness_sha256": "a" * 64,
        "witness_minimized_bytes": 142,
        "embargo_days": 90,
        "embargo_until": "2026-09-10",
        "summary": (
            "A divergence was observed between libwebp and an alternative "
            "decoder when processing a structured input. The behavior is "
            "reproducible and documented under a private hash-chained "
            "ledger. We are not asserting an exploit; we are reporting a "
            "differential decode outcome for triage."
        ),
        "reproduction_environment": "ubuntu-22.04, libwebp 1.3.0",
        "cve_request_target": "Chrome CNA via chromium-security@chromium.org",
    }


def test_vendor_initial_email_renders_without_blocking_flags() -> None:
    context = _safe_context()
    rendered = render("vendor_initial_email.j2", context)
    assert "AG-DIS-IMG-0001" in rendered
    assert "libwebp upstream" in rendered
    # The rendered output must pass safety scanning.
    flags = scan_record({"rendered_email": rendered})
    blocks = blocking_flags(flags)
    assert not blocks, f"vendor_initial_email triggered: {[f.rule for f in blocks]}"


def test_reproduction_steps_template_uses_hash_only_no_payload_bytes() -> None:
    context = _safe_context()
    rendered = render("reproduction_steps.j2", context)
    # Reference by hash, not bytes
    assert "a" * 64 in rendered
    assert "142" in rendered  # minimized_bytes
    # No words that imply embedded payload
    lowered = rendered.lower()
    assert "raw_bytes" not in lowered
    assert "raw bytes" not in lowered
    assert "payload_b64" not in lowered
    flags = scan_record({"rendered_steps": rendered})
    blocks = blocking_flags(flags)
    assert not blocks, f"reproduction_steps triggered: {[f.rule for f in blocks]}"


def test_cve_request_template_renders_chrome_cna_variant() -> None:
    context = _safe_context()
    context["cna_variant"] = "chrome_cna"
    rendered = render("cve_request.j2", context)
    assert "Chrome" in rendered or "chromium" in rendered.lower()
    assert "AG-DIS-IMG-0001" in rendered
    flags = scan_record({"rendered_cve_request": rendered})
    blocks = blocking_flags(flags)
    assert not blocks


def test_cve_request_template_renders_mitre_variant() -> None:
    context = _safe_context()
    context["cna_variant"] = "mitre_direct"
    rendered = render("cve_request.j2", context)
    assert "MITRE" in rendered or "mitre" in rendered.lower()
    flags = scan_record({"rendered_cve_request": rendered})
    assert not blocking_flags(flags)


def test_cve_request_template_renders_github_advisory_variant() -> None:
    context = _safe_context()
    context["cna_variant"] = "github_security_advisory"
    rendered = render("cve_request.j2", context)
    assert "GitHub" in rendered or "advisory" in rendered.lower()
    flags = scan_record({"rendered_cve_request": rendered})
    assert not blocking_flags(flags)


def test_router_provided_context_renders_clean() -> None:
    """End-to-end: a vendor route from the registry can be fed straight
    into the template renderer and still produce a clean output."""
    route = vcr.route("libwebp_upstream")
    context = _safe_context()
    context["vendor_name"] = route.name
    context["vendor_contact"] = route.primary_contact
    context["embargo_days"] = route.default_embargo_days
    rendered = render("vendor_initial_email.j2", context)
    flags = scan_record({"rendered_email": rendered})
    assert not blocking_flags(flags)
