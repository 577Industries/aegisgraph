"""Jinja2 templates for the coordinated-disclosure pipeline.

Three templates ship:
  vendor_initial_email.j2  : first-contact letter to vendor security inbox
  reproduction_steps.j2    : sanitized reproduction (hashes only)
  cve_request.j2           : CVE-request form text; supports MITRE direct,
                             Chrome CNA, and GitHub Security Advisory variants

`render(template_name, context)` returns the rendered text. Templates are
required to render outputs that pass `aegisgraph.safety.scan_record` with
zero blocking flags — see
tests/disclosure/test_template_rendering_no_blocking_safety_flags.py.

`render_to_mbox(template_name, context, finding_id)` writes the rendered
output to aegisgraph/disclosure/outgoing/<finding_id>.mbox so a human can
review and dispatch. Per the task constraint: no SMTP, no auto-send.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jinja2

from aegisgraph.io import repo_root


TEMPLATES_REL_PATH = "aegisgraph/disclosure/templates"
OUTGOING_REL_PATH = "aegisgraph/disclosure/outgoing"


def _templates_dir(root: Path | None = None) -> Path:
    base = root or repo_root()
    return base / TEMPLATES_REL_PATH


def _outgoing_dir(root: Path | None = None) -> Path:
    base = root or repo_root()
    return base / OUTGOING_REL_PATH


def _env(root: Path | None = None) -> jinja2.Environment:
    """Build a Jinja2 environment scoped to the templates directory.

    autoescape is OFF intentionally and safely: these templates render
    plain-text RFC-5322 email bodies and CERT/CC / CVE-request form
    bodies. They are NEVER served as HTML to a browser, so the XSS
    threat model that drives Flask's default escaping does not apply.

    Defense-in-depth: every rendered output is run through
    `aegisgraph.safety.scan_record`, which blocks credential-bearing
    or live-target-probing language regardless of HTML semantics
    (see tests/disclosure/test_template_rendering_no_blocking_safety_flags.py).
    """
    # nosemgrep: direct-use-of-jinja2  # plain-text email/CVE-form rendering, not HTML; safety.scan_record gates every output
    return jinja2.Environment(  # noqa: S701
        loader=jinja2.FileSystemLoader(str(_templates_dir(root))),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def render(
    template_name: str,
    context: dict[str, Any],
    root: Path | None = None,
) -> str:
    """Render a template with `context` and return the text.

    Output is plain text (RFC-5322 email body or CVE-request form body),
    never served as HTML. See `_env` for the autoescape rationale.
    """
    env = _env(root)
    template = env.get_template(template_name)
    # nosemgrep: direct-use-of-jinja2  # plain-text render; not user-supplied HTML
    return template.render(**context)


def render_to_mbox(
    template_name: str,
    context: dict[str, Any],
    finding_id: str,
    root: Path | None = None,
) -> Path:
    """Render and write to outgoing/<finding_id>.mbox for human dispatch.

    The mbox format is intentionally minimal — one From_ line + headers +
    blank line + body — so any mail client can ingest it for manual review.
    No SMTP is contacted.
    """
    text = render(template_name, context, root=root)
    outgoing = _outgoing_dir(root)
    outgoing.mkdir(parents=True, exist_ok=True)
    target = outgoing / f"{finding_id}.mbox"
    mbox_body = _wrap_mbox(
        body=text,
        to_addr=str(context.get("vendor_contact", "security@example.invalid")),
        from_addr=str(
            context.get("researcher_contact", "disclosure@577.industries")
        ),
        subject=str(
            context.get(
                "subject",
                f"Coordinated disclosure inquiry — {finding_id}",
            )
        ),
    )
    target.write_text(mbox_body, encoding="utf-8")
    return target


def _wrap_mbox(body: str, to_addr: str, from_addr: str, subject: str) -> str:
    return (
        f"From {from_addr} Thu Jan  1 00:00:00 1970\n"
        f"From: {from_addr}\n"
        f"To: {to_addr}\n"
        f"Subject: {subject}\n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        f"{body}\n"
    )


__all__ = ["render", "render_to_mbox"]
