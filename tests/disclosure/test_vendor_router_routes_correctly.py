"""vendor_contact_router routes finding ids to the right vendor entry.

The router reads aegisgraph/disclosure/vendor_registry.yaml and exposes a
lookup that resolves a vendor_id (or a finding's `target` field) to the
canonical contact + CNA path + embargo defaults. Routing failures raise
VendorNotRegisteredError — the disclosure pipeline must fail-closed when
asked to contact an unknown vendor, never auto-fallback.
"""

from __future__ import annotations

import pytest

from aegisgraph.disclosure.pipeline import vendor_contact_router as vcr


def test_libwebp_routes_to_chrome_cna() -> None:
    """libwebp_upstream is the recommended Option A first-disclosure target.
    Routing it must surface security@chromium.org + chrome_cna path."""
    route = vcr.route("libwebp_upstream")
    assert route.vendor_id == "libwebp_upstream"
    assert route.primary_contact == "security@chromium.org"
    assert route.cna_path == "chrome_cna"
    assert route.default_embargo_days == 90


def test_element_hq_routes_to_github_security_advisories() -> None:
    """Element / matrix.org uses GH Security Advisories per Option C."""
    route = vcr.route("element_hq")
    assert route.vendor_id == "element_hq"
    assert route.primary_contact == "security@element.io"
    assert route.cna_path == "github_security_advisory"


def test_unknown_vendor_raises_fail_closed() -> None:
    """The router must NEVER silently auto-route to CERT/CC. Failing closed
    forces the human in the loop to update vendor_registry.yaml first."""
    with pytest.raises(vcr.VendorNotRegisteredError) as exc:
        vcr.route("acme_corp_we_have_never_heard_of")
    # error message names the vendor so the operator knows what to add
    assert "acme_corp" in str(exc.value)


def test_cna_path_resolution_returns_url() -> None:
    """route(...).cna_path resolves through the cna_paths block in YAML
    to a URL. This is what the cve_request template renders."""
    route = vcr.route("libwebp_upstream")
    cna_info = vcr.resolve_cna_path(route.cna_path)
    assert cna_info["url"].startswith("https://")
    assert "chromium" in cna_info["url"].lower()


def test_route_for_finding_extracts_vendor_from_finding_record() -> None:
    """A finding dict carries a `target` or `vendor_id` field. The router
    reads it and dispatches. This is the integration shape the
    embargo_timer + workbench will call."""
    finding = {
        "id": "AG-DIS-IMG-0001",
        "vendor_id": "libwebp_upstream",
        "target": "libwebp",
    }
    route = vcr.route_for_finding(finding)
    assert route.vendor_id == "libwebp_upstream"


def test_route_for_finding_without_vendor_id_raises() -> None:
    """A finding with no vendor_id and no resolvable target must fail.
    The disclosure pipeline never guesses."""
    finding = {"id": "AG-DIS-IMG-0099"}
    with pytest.raises(vcr.VendorNotRegisteredError):
        vcr.route_for_finding(finding)


def test_list_vendors_returns_at_least_seven_registered() -> None:
    """vendor_registry.yaml ships with 7 entries (signal, element, libwebp,
    libavif, libheif, wire, telegram). Surface them all."""
    vendors = vcr.list_vendors()
    assert len(vendors) >= 7
    ids = {v.vendor_id for v in vendors}
    assert "libwebp_upstream" in ids
    assert "signal_foundation" in ids
    assert "element_hq" in ids
