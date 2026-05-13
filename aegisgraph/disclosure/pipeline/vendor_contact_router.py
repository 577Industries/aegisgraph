"""Vendor lookup + routing via aegisgraph/disclosure/vendor_registry.yaml.

Per ADR-0006: per-vendor contacts live as DATA. This module is the read
path. It does NOT send anything; it returns route information for the
template + ledger layers.

Fail-closed: unknown vendors raise VendorNotRegisteredError. The
disclosure pipeline never auto-falls-back to CERT/CC silently — that's
an explicit human decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from aegisgraph.io import repo_root


REGISTRY_REL_PATH = "aegisgraph/disclosure/vendor_registry.yaml"


class VendorNotRegisteredError(LookupError):
    """Raised when a vendor_id is not present in vendor_registry.yaml.

    The disclosure pipeline must fail-closed here: silently substituting
    CERT/CC for an unknown vendor would risk contacting the wrong party.
    Update the YAML first, then re-run.
    """


@dataclass(frozen=True)
class VendorRoute:
    """A resolved vendor routing decision.

    Surfaces the fields the templates + cve_request layer need without
    leaking the full YAML record (which may carry free-form `notes`).
    """

    vendor_id: str
    name: str
    primary_contact: str
    secondary_contact: str | None
    cna_status: str
    cna_path: str
    default_embargo_days: int
    fallback_contacts: tuple[str, ...]


def _registry_path(root: Path | None = None) -> Path:
    base = root or repo_root()
    return base / REGISTRY_REL_PATH


def _load_registry(root: Path | None = None) -> dict[str, Any]:
    """Parse vendor_registry.yaml. Cached per-call to keep tests isolated."""
    path = _registry_path(root)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(
            f"vendor_registry.yaml at {path} did not parse as a mapping"
        )
    return data


def _vendor_entry_to_route(vendor_id: str, entry: dict[str, Any]) -> VendorRoute:
    fallback = tuple(entry.get("fallback_contacts") or ())
    return VendorRoute(
        vendor_id=vendor_id,
        name=str(entry.get("name", vendor_id)),
        primary_contact=str(entry["primary_contact"]),
        secondary_contact=entry.get("secondary_contact"),
        cna_status=str(entry.get("cna_status", "none")),
        cna_path=str(entry.get("cna_path", "mitre_direct")),
        default_embargo_days=int(entry.get("default_embargo_days", 90)),
        fallback_contacts=fallback,
    )


def route(vendor_id: str, root: Path | None = None) -> VendorRoute:
    """Resolve `vendor_id` against the registry. Raises if absent."""
    registry = _load_registry(root)
    vendors = registry.get("vendors", {})
    if vendor_id not in vendors:
        known = ", ".join(sorted(vendors.keys()))
        raise VendorNotRegisteredError(
            f"vendor {vendor_id!r} is not registered in vendor_registry.yaml; "
            f"known vendors: {known}. Add the vendor (with counsel review) "
            "before invoking the disclosure pipeline."
        )
    return _vendor_entry_to_route(vendor_id, vendors[vendor_id])


def route_for_finding(
    finding: dict[str, Any], root: Path | None = None
) -> VendorRoute:
    """Resolve a finding dict to its vendor route.

    Reads `vendor_id` first; falls back to `target` if it matches a
    registered vendor_id. If neither resolves, raises.
    """
    vendor_id = finding.get("vendor_id") or finding.get("target")
    if not vendor_id:
        raise VendorNotRegisteredError(
            f"finding {finding.get('id', '<unknown>')!r} carries neither "
            "vendor_id nor target; cannot route. Set vendor_id explicitly."
        )
    return route(str(vendor_id), root=root)


def resolve_cna_path(cna_path_id: str, root: Path | None = None) -> dict[str, Any]:
    """Return the cna_paths.<id> block (url + notes + backlog stats)."""
    registry = _load_registry(root)
    cna_paths = registry.get("cna_paths", {})
    if cna_path_id not in cna_paths:
        known = ", ".join(sorted(cna_paths.keys()))
        raise VendorNotRegisteredError(
            f"cna_path {cna_path_id!r} not found in vendor_registry.yaml; "
            f"known paths: {known}"
        )
    return dict(cna_paths[cna_path_id])


def list_vendors(root: Path | None = None) -> list[VendorRoute]:
    """Return every registered vendor as a VendorRoute."""
    registry = _load_registry(root)
    vendors = registry.get("vendors", {})
    return [
        _vendor_entry_to_route(vendor_id, entry)
        for vendor_id, entry in vendors.items()
    ]
