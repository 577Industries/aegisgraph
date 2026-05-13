"""Reviewer-workbench link mapper.

The workbench (under separate development) hosts a private UI for
authorized reviewers to inspect a finding's full chain. Until the
workbench has a real base URL, this module provides a stable
deterministic placeholder mapping so other pipeline modules + the
vendor-initial-email template can link to "the finding view".

Per ADR-0006: workbench URLs are engineering-private; the public
sanitized projection of disclosure events strips them out.
"""

from __future__ import annotations

from dataclasses import dataclass


# Placeholder base URL until the workbench ships. The integration
# stream will replace this with a real URL via a config block in
# vendor_registry.yaml or a dedicated workbench.yaml.
DEFAULT_WORKBENCH_BASE = "https://workbench.577.industries/disclosure"


@dataclass(frozen=True)
class WorkbenchLink:
    finding_id: str
    url: str
    visibility: str = "engineering_private"


def link_for(
    finding_id: str, base_url: str = DEFAULT_WORKBENCH_BASE
) -> WorkbenchLink:
    """Compose the placeholder workbench URL for a finding.

    Format: <base>/findings/<finding_id>
    The finding_id is path-safe per its schema regex
    (^AG-(EV|CRASH|DIS|IV|XSMA)-[A-Z0-9-]+$).
    """
    if not finding_id:
        raise ValueError("finding_id is required to compose a workbench link")
    url = f"{base_url.rstrip('/')}/findings/{finding_id}"
    return WorkbenchLink(finding_id=finding_id, url=url)


def map_findings(finding_ids: list[str]) -> dict[str, str]:
    """Bulk-map finding_id -> url. Convenience for templates."""
    return {fid: link_for(fid).url for fid in finding_ids}
